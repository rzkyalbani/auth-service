import { ConflictException, Injectable } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { RegisterAuthDto } from './dto/register-auth.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(private usersService: UsersService) {}

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
}
