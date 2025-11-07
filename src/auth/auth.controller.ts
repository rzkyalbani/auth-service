import {
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
import { AuthService } from './auth.service';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { LoginAuthDto } from './dto/login-auth.dto';
import { LocalStrategy } from './strategies/local.strategies';
import { JwtRefreshGuard } from './guards/jwt-refresh.guard';
import { Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private localStrategy: LocalStrategy,
  ) {}

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

  @HttpCode(HttpStatus.OK)
  @Post('login')
  async login(
    @Body(new ValidationPipe())
    loginDto: LoginAuthDto,
  ) {
    const user = await this.localStrategy.validate(
      loginDto.email,
      loginDto.password,
    );
    return this.authService.login(user);
  }

  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtRefreshGuard)
  @Post('refresh')
  async refreshToken(@Request() req) {
    const userPayload = req.user;

    return this.authService.refreshTokens(userPayload);
  }

  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtRefreshGuard)
  @Post('logout')
  async logout(@Request() req) {
    return this.authService.logout(req.user);
  }

  @HttpCode(HttpStatus.OK)
  @Get('verify-email')
  async verifyEmail(
    @Query('token') token: string,
    @Res() res: Response,
  ) {
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
}
