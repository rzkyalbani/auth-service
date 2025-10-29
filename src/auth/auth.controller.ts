import { Body, Controller, Post, ValidationPipe } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterAuthDto } from './dto/register-auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

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
}
