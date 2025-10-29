import {
  Body,
  Controller,
  Post,
  Request,
  UseGuards,
  ValidationPipe,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { LoginAuthDto } from './dto/login-auth.dto';
import { LocalStrategy } from './strategies/local.strategies';

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
}
