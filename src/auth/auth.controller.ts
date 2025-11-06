import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Request,
  UseGuards,
  ValidationPipe,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { LoginAuthDto } from './dto/login-auth.dto';
import { LocalStrategy } from './strategies/local.strategies';
import { JwtRefreshGuard } from './guards/jwt-refresh.guard';

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
}
