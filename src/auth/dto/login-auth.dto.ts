import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class LoginAuthDto {
  @ApiProperty({
    description: 'Email pengguna yang terdaftar',
    example: 'user@example.com',
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({
    description: 'Password pengguna (minimal 8 karakter)',
    example: 'password123',
  })
  @IsString()
  @IsNotEmpty()
  password: string;
}
