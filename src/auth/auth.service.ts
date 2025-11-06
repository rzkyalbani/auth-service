import {
  ConflictException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { RegisterAuthDto } from './dto/register-auth.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { User } from 'generated/prisma/client';
import { RedisService } from 'src/redis/redis.service';
import * as crypto from 'crypto';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private redisService: RedisService,
  ) {}

  async register(registerDto: RegisterAuthDto) {
    const userExists = await this.usersService.findOneByEmail(
      registerDto.email,
    );

    if (userExists) {
      throw new ConflictException('Email already registered');
    }

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(registerDto.password, saltRounds);

    try {
      const newUser = await this.usersService.create({
        email: registerDto.email,
        displayName: registerDto.displayName,
        passwordHash,
        provider: 'LOCAL',
      });

      const { passwordHash: removedHash, ...result } = newUser;
      return result;
    } catch (error) {
      throw new ConflictException('Could not create user');
    }
  }

  async validateUser(email: string, pass: string): Promise<any> {
    const user = await this.usersService.findOneByEmail(email);

    if (user && (await bcrypt.compare(pass, user.passwordHash as string))) {
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
}
