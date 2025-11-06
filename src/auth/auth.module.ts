import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from 'src/users/users.module';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { LocalStrategy } from './strategies/local.strategies';
import { JwtRefreshStrategy } from './strategies/jwt-refresh.strategy';
import { RedisModule } from 'src/redis/redis.module';

@Module({
  imports: [UsersModule, PassportModule, JwtModule.register({}), RedisModule],
  providers: [AuthService, LocalStrategy, JwtRefreshStrategy],
  controllers: [AuthController],
})
export class AuthModule {}
