import {
  ConflictException,
  ForbiddenException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { RegisterAuthDto } from './dto/register-auth.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { User } from 'generated/prisma/client';
import { RedisService } from 'src/redis/redis.service';
import * as crypto from 'crypto';
import { MailService } from 'src/mail/mail.service';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { RequestPasswordResetDto } from './dto/request-password-reset.dto';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private redisService: RedisService,
    private mailService: MailService,
    private prisma: PrismaService,
  ) {}

  async register(registerDto: RegisterAuthDto) {
    const userExists = await this.usersService.findOneByEmail(
      registerDto.email,
    );

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(registerDto.password, saltRounds);

    if (userExists) {
      if (userExists.emailVerifiedAt) {
        throw new ConflictException('Email already registered and verified.');
      }

      try {
        const updatedUser = await this.usersService.updateRegistrationData(
          userExists.id,
          {
            displayName: registerDto.displayName,
            passwordHash: passwordHash,
          },
        );

        await this.sendVerificationEmail(updatedUser);

        const { passwordHash: removedHash, ...result } = updatedUser;
        return result;
      } catch (error) {
        throw new ConflictException('Could not update user');
      }
    }

    try {
      const newUser = await this.usersService.create({
        email: registerDto.email,
        displayName: registerDto.displayName,
        passwordHash,
        provider: 'LOCAL',
      });

      const verificationToken = crypto.randomUUID();

      await this.redisService.set(
        `verify-email:${verificationToken}`,
        newUser.id,
        'EX',
        3600,
      );

      await this.sendVerificationEmail(newUser);

      const { passwordHash: removedHash, ...result } = newUser;
      return result;
    } catch (error) {
      throw new ConflictException('Could not create user');
    }
  }

  async validateUser(email: string, pass: string): Promise<any> {
    const emailString = String(email);
    const passString = String(pass);

    const user = await this.usersService.findOneByEmail(emailString);

    if (
      user &&
      (await bcrypt.compare(passString, user.passwordHash as string))
    ) {
      if (!user.emailVerifiedAt) {
        throw new UnauthorizedException(
          'Please verify your email before logging in.',
        );
      }

      const { passwordHash: removedHash, ...result } = user;
      return result;
    }

    return null;
  }

  async getTokens(user: User) {
    const jti = crypto.randomUUID();

    const accessTokenPayload = {
      sub: user.id,
      email: user.email,
    };
    const refreshTokenPayload = {
      sub: user.id,
      jti,
    };

    const accessTokenSecret = this.configService.get<string>('JWT_SECRET');
    const accessTokenExpiresIn = this.configService.get<string>(
      'ACCESS_TOKEN_EXPIRES_IN',
    );
    const refreshTokenSecret =
      this.configService.get<string>('JWT_REFRESH_SECRET');
    const refreshTokenExpiresIn = this.configService.get<string>(
      'REFRESH_TOKEN_EXPIRES_IN',
    );

    const redisExpiresInSeconds = 7 * 24 * 60 * 60;

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(accessTokenPayload, {
        secret: accessTokenSecret,
        expiresIn: accessTokenExpiresIn as any,
      }),
      this.jwtService.signAsync(refreshTokenPayload, {
        secret: refreshTokenSecret,
        expiresIn: refreshTokenExpiresIn as any,
      }),
    ]);

    await this.redisService.set(
      `session:${jti}`,
      user.id,
      'EX',
      redisExpiresInSeconds,
    );

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  async login(user: any) {
    return this.getTokens(user);
  }

  async refreshTokens(payload: any) {
    const userId = payload.sub;
    const jti = payload.jti;

    const sessionKey = `session:${jti}`;
    const sessionUserId = await this.redisService.get(sessionKey);

    if (!sessionUserId) {
      throw new ForbiddenException('Refresh token is invalid or has been used');
    }

    if (sessionUserId !== userId) {
      throw new ForbiddenException('Access Denied');
    }

    await this.redisService.del(sessionKey);

    const user = await this.usersService.findOneById(userId);
    if (!user) {
      throw new ForbiddenException('Access Denied');
    }

    return this.getTokens(user);
  }

  async logout(payload: any) {
    const jti = payload.jti;
    const sessionKey = `session:${jti}`;

    await this.redisService.del(sessionKey);

    return { message: 'Logged out successfully' };
  }

  async verifyEmail(token: string) {
    const tokenKey = `verify-email:${token}`;

    const userId = await this.redisService.get(tokenKey);

    if (!userId) {
      throw new ForbiddenException('Invalid or expired verification token');
    }

    try {
      await this.usersService.updateEmailVerified(userId);
    } catch (error) {
      throw new ConflictException('User not found or already verified');
    }

    await this.redisService.del(tokenKey);

    return { message: 'Email verified successfully' };
  }

  private async sendVerificationEmail(user: User) {
    const verificationToken = crypto.randomUUID();
    await this.redisService.set(
      `verify-email:${verificationToken}`,
      user.id,
      'EX',
      3600,
    );
    this.mailService.sendUserVerification(user, verificationToken);
  }

  async requestPasswordReset(dto: RequestPasswordResetDto) {
    const { email } = dto;
    const user = await this.usersService.findOneByEmail(email);

    if (user && user.emailVerifiedAt) {
      const resetToken = crypto.randomUUID();

      await this.redisService.set(
        `reset-pass:${resetToken}`,
        user.id,
        'EX',
        900,
      );

      this.mailService.sendPasswordReset(user, resetToken);
    }

    return {
      message:
        'If a user with that email exists, a password reset link has been sent.',
    };
  }

  async resetPassword(dto: ResetPasswordDto) {
    const { token, newPassword } = dto;
    const tokenKey = `reset-pass:${token}`;

    const userId = await this.redisService.get(tokenKey);
    if (!userId) {
      throw new ForbiddenException('Invalid or expired password reset token');
    }

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(newPassword, saltRounds);

    try {
      await this.usersService.updatePassword(userId, passwordHash); // <-- Kita perlu buat ini
    } catch (error) {
      throw new ConflictException('User not found');
    }

    await this.redisService.del(tokenKey);

    return { message: 'Password has been reset successfully' };
  }

  async validateOAuthUser(profile: {
    provider: string;
    providerId: string;
    email: string;
    displayName: string;
    picture: string;
  }) {
    try {
      const oauthAccount = await this.prisma.oAuthAccount.findUnique({
        where: {
          provider_providerId: {
            provider: profile.provider,
            providerId: profile.providerId,
          },
        },
        include: { user: true },
      });

      if (oauthAccount) {
        return oauthAccount.user;
      }

      const userByEmail = await this.usersService.findOneByEmail(profile.email);

      if (userByEmail) {
        await this.prisma.oAuthAccount.create({
          data: {
            provider: profile.provider,
            providerId: profile.providerId,
            displayName: profile.displayName,
            picture: profile.picture,
            userId: userByEmail.id,
          },
        });

        if (!userByEmail.emailVerifiedAt) {
          return this.usersService.updateEmailVerified(userByEmail.id);
        }
        return userByEmail;
      }

      const newUser = await this.prisma.user.create({
        data: {
          email: profile.email,
          displayName: profile.displayName,
          provider: 'GOOGLE',
          emailVerifiedAt: new Date(),
          oauthAccounts: {
            create: {
              provider: profile.provider,
              providerId: profile.providerId,
              displayName: profile.displayName,
              picture: profile.picture,
            },
          },
        },
      });

      return newUser;
    } catch (error) {
      throw new InternalServerErrorException('Failed to process OAuth user');
    }
  }
}
