import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  Request,
  Res,
  UseGuards,
  ValidationPipe,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { LoginAuthDto } from './dto/login-auth.dto';
import { LocalStrategy } from './strategies/local.strategies';
import { JwtRefreshGuard } from './guards/jwt-refresh.guard';
import { Response } from 'express';
import { RequestPasswordResetDto } from './dto/request-password-reset.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { GoogleAuthGuard } from './guards/google-auth.guard';
import { User } from 'generated/prisma/client';
import { ConfigService } from '@nestjs/config';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import * as qrcode from 'qrcode';
import { TwoFaCodeDto } from './dto/2fa-code.dto';
import { Throttle } from '@nestjs/throttler';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private localStrategy: LocalStrategy,
    private configService: ConfigService,
  ) {}

  @ApiOperation({
    summary: 'Register Pengguna',
    description: 'Mendaftarkan pengguna baru dan mengirim email verifikasi.',
  })
  @ApiResponse({ status: 201, description: 'User berhasil didaftarkan.' })
  @ApiResponse({
    status: 409,
    description: 'Email sudah terdaftar atau konflik lain.',
  })
  @Post('register')
  async register(
    @Body(new ValidationPipe())
    registerDto: RegisterAuthDto,
  ) {
    const user = await this.authService.register(registerDto);
    return {
      message: 'User registered successfully',
      data: user,
    };
  }

  @ApiOperation({
    summary: 'Login Pengguna',
    description:
      'Mendapatkan Access Token & Refresh Token jika kredensial valid.',
  })
  @ApiResponse({
    status: 200,
    description: 'Login berhasil, mengembalikan tokens.',
  })
  @ApiResponse({
    status: 401,
    description: 'Kredensial salah atau email belum diverifikasi.',
  })
  @Throttle({
    default: {
      ttl: 60000,
      limit: 5,
    },
  })
  @HttpCode(HttpStatus.OK)
  @Post('login')
  async login(@Body() loginDto: LoginAuthDto) {
    const user = await this.localStrategy.validate(
      loginDto.email,
      loginDto.password,
    );

    if (user.twoFAEnabled) {
      return {
        message: '2FA code required',
        twoFARequired: true,
        userId: user.id,
      };
    }

    return this.authService.login(user);
  }

  @Post('2fa/verify-login')
  @HttpCode(HttpStatus.OK)
  async verifyLogin2FA(@Body() dto: TwoFaCodeDto & { userId: string }) {
    if (!dto.userId) {
      throw new BadRequestException('userId is required');
    }
    return this.authService.verify2FALogin(dto.userId, dto.code);
  }

  @ApiOperation({
    summary: 'Refresh Token',
    description: 'Mendapatkan access token baru menggunakan refresh token.',
  })
  @ApiBearerAuth()
  @ApiResponse({ status: 200, description: 'Tokens berhasil direfresh.' })
  @ApiResponse({ status: 403, description: 'Refresh token tidak valid.' })
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtRefreshGuard)
  @Post('refresh')
  async refreshToken(@Request() req) {
    const userPayload = req.user;

    return this.authService.refreshTokens(userPayload);
  }

  @ApiOperation({
    summary: 'Logout',
    description: 'Menghapus session refresh token (logout).',
  })
  @ApiBearerAuth()
  @ApiResponse({ status: 200, description: 'Berhasil logout.' })
  @ApiResponse({ status: 403, description: 'Refresh token tidak valid.' })
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtRefreshGuard)
  @Post('logout')
  async logout(@Request() req) {
    return this.authService.logout(req.user);
  }

  @ApiOperation({
    summary: 'Verifikasi Email',
    description: 'Memverifikasi email pengguna menggunakan token.',
  })
  @ApiResponse({ status: 200, description: 'Email berhasil diverifikasi.' })
  @ApiResponse({
    status: 403,
    description: 'Token verifikasi tidak valid atau kadaluarsa.',
  })
  @HttpCode(HttpStatus.OK)
  @Get('verify-email')
  async verifyEmail(@Query('token') token: string, @Res() res: Response) {
    if (!token) {
      return res.status(400).send('Missing verification token');
    }

    try {
      await this.authService.verifyEmail(token);

      return res.redirect('http://localhost:3001/login?verified=true');
    } catch (error) {
      return res.status(error.getStatus() || 500).send(error.message);
    }
  }

  @ApiOperation({
    summary: 'Request Password Reset',
    description:
      'Mengirimkan email berisi token untuk reset password jika akun ada.',
  })
  @ApiResponse({
    status: 200,
    description: 'Jika akun ada, email reset telah dikirim.',
  })
  @ApiResponse({ status: 400, description: 'Permintaan tidak valid.' })
  @HttpCode(HttpStatus.OK)
  @Post('request-password-reset')
  async requestPasswordReset(
    @Body(new ValidationPipe()) dto: RequestPasswordResetDto,
  ) {
    return this.authService.requestPasswordReset(dto);
  }

  @ApiOperation({
    summary: 'Reset Password',
    description:
      'Mereset password menggunakan token yang dikirim melalui email.',
  })
  @ApiResponse({ status: 200, description: 'Password berhasil direset.' })
  @ApiResponse({
    status: 403,
    description: 'Token tidak valid atau kadaluarsa.',
  })
  @HttpCode(HttpStatus.OK)
  @Post('reset-password')
  async resetPassword(@Body(new ValidationPipe()) dto: ResetPasswordDto) {
    return this.authService.resetPassword(dto);
  }

  @Get('google')
  @UseGuards(GoogleAuthGuard)
  async googleAuth() {}

  @Get('google/callback')
  @UseGuards(GoogleAuthGuard)
  async googleAuthCallback(@Request() req, @Res() res: Response) {
    const user = req.user as User;

    if (!user) {
      res.redirect(
        `${this.configService.get<string>('FRONTEND_URL')}/login?error=true`,
      );
      return;
    }

    const tokens = await this.authService.getTokens(user);

    const frontendUrl = this.configService.get<string>('FRONTEND_URL');

    res.redirect(
      `${frontendUrl}/auth-callback?access_token=${tokens.access_token}&refresh_token=${tokens.refresh_token}`,
    );
  }

  @ApiOperation({ summary: 'Generate QR Code untuk 2FA' })
  @ApiBearerAuth()
  @ApiResponse({ status: 200, description: 'Mengembalikan data URL QR Code' })
  @ApiResponse({ status: 401, description: 'Unauthorized (Token tidak valid)' })
  @Post('2fa/setup')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  async setup2FA(@Request() req, @Res() res: Response) {
    const user = req.user as User;

    const otpauthUrl = await this.authService.generate2FASecret(user);

    const qrCodeDataUrl = await qrcode.toDataURL(otpauthUrl);

    res.json({ qrCodeUrl: qrCodeDataUrl });
  }

  @ApiOperation({
    summary: 'Enable 2FA',
    description: 'Mengaktifkan 2FA untuk user setelah memverifikasi kode.',
  })
  @ApiBearerAuth()
  @ApiResponse({ status: 200, description: '2FA berhasil diaktifkan.' })
  @ApiResponse({ status: 401, description: 'Unauthorized (Token tidak valid)' })
  @Post('2fa/enable')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  async enable2FA(
    @Request() req,
    @Body(new ValidationPipe()) dto: TwoFaCodeDto,
  ) {
    const user = req.user as User;
    return this.authService.enable2FA(user.id, dto.code);
  }
}
