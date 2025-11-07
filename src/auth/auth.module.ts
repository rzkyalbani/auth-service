import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from 'src/users/users.module';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { LocalStrategy } from './strategies/local.strategies';
import { JwtRefreshStrategy } from './strategies/jwt-refresh.strategy';
import { RedisModule } from 'src/redis/redis.module';
import { MailModule } from 'src/mail/mail.module';
import { GoogleStrategy } from './strategies/google.strategy';
import { PrismaModule } from 'src/prisma/prisma.module';
import { JwtStrategy } from './strategies/jwt.strategy';
import { EncryptionModule } from 'src/common/encryption/encryption.module';
import { EncryptionService } from 'src/common/encryption/encryption.service';

@Module({
  imports: [
    UsersModule,
    PassportModule,
    JwtModule.register({}),
    RedisModule,
    MailModule,
    PrismaModule,
    EncryptionModule,
  ],
  providers: [
    AuthService,
    LocalStrategy,
    JwtRefreshStrategy,
    GoogleStrategy,
    JwtStrategy,
    EncryptionService,
  ],
  controllers: [AuthController],
})
export class AuthModule {}
