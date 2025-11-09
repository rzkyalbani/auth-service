// src/auth/auth.service.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { UsersService } from 'src/users/users.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { RedisService } from 'src/redis/redis.service';
import { MailService } from 'src/mail/mail.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { EncryptionService } from 'src/common/encryption/encryption.service';
import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { User } from 'generated/prisma/client';

const mockUser: User = {
  id: 'user-123',
  email: 'test@example.com',
  passwordHash: 'hashed-password',
  displayName: 'Test User',
  emailVerifiedAt: new Date(),
  provider: 'LOCAL',
  twoFAEnabled: false,
  twoFASecretEnc: null,
  createdAt: new Date(),
  updatedAt: new Date(),
};

const mockUsersService = {
  findOneByEmail: jest.fn(),
  findOneById: jest.fn().mockResolvedValue(mockUser),
  updateEmailVerified: jest.fn(),
  updatePassword: jest.fn(),
  set2FASecret: jest.fn(),
  set2FAEnabled: jest.fn(),
};

const mockJwtService = {
  signAsync: jest.fn().mockResolvedValue('mock-jwt-token'),
};

const mockConfigService = {
  get: jest.fn((key: string) => {
    if (key === 'JWT_SECRET') return 'secret';
    if (key === 'JWT_REFRESH_SECRET') return 'refresh-secret';
    if (key === 'ACCESS_TOKEN_EXPIRES_IN') return '15m';
    if (key === 'REFRESH_TOKEN_EXPIRES_IN') return '7d';
    return null;
  }),
};

const mockRedisService = {
  set: jest.fn().mockResolvedValue('OK'),
  get: jest.fn(),
  del: jest.fn().mockResolvedValue(1),
};

const mockMailService = {
  sendUserVerification: jest.fn(),
  sendPasswordReset: jest.fn(),
};

const mockPrismaService = {
  oAuthAccount: {
    findUnique: jest.fn(),
    create: jest.fn(),
  },
  user: {
    create: jest.fn(),
  },
};

const mockEncryptionService = {
  encrypt: jest.fn().mockReturnValue('encrypted-secret'),
  decrypt: jest.fn().mockReturnValue('decrypted-secret'),
};

describe('AuthService', () => {
  let service: AuthService;
  let redisService: RedisService;
  let usersService: UsersService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: UsersService, useValue: mockUsersService },
        { provide: JwtService, useValue: mockJwtService },
        { provide: ConfigService, useValue: mockConfigService },
        { provide: RedisService, useValue: mockRedisService },
        { provide: MailService, useValue: mockMailService },
        { provide: PrismaService, useValue: mockPrismaService },
        { provide: EncryptionService, useValue: mockEncryptionService },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    redisService = module.get<RedisService>(RedisService);
    usersService = module.get<UsersService>(UsersService);

    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('refreshTokens', () => {
    const mockPayload = { sub: 'user-123', jti: 'jti-abc' };

    it('should refresh tokens successfully if JTI is valid', async () => {
      (mockRedisService.get as jest.Mock).mockResolvedValue('user-123');
      (mockUsersService.findOneById as jest.Mock).mockResolvedValue(mockUser);

      const result = await service.refreshTokens(mockPayload);

      expect(result).toHaveProperty('access_token');
      expect(result).toHaveProperty('refresh_token');

      expect(redisService.del).toHaveBeenCalledWith('session:jti-abc');
      expect(usersService.findOneById).toHaveBeenCalledWith('user-123');
      expect(redisService.set).toHaveBeenCalled();
    });

    it('should throw ForbiddenException if JTI is not in Redis', async () => {
      (mockRedisService.get as jest.Mock).mockResolvedValue(null);

      await expect(service.refreshTokens(mockPayload)).rejects.toThrow(
        ForbiddenException,
      );

      expect(redisService.del).not.toHaveBeenCalled();
      expect(usersService.findOneById).not.toHaveBeenCalled();
    });

    it('should throw ForbiddenException if JTI user ID does not match payload user ID', async () => {
      (mockRedisService.get as jest.Mock).mockResolvedValue('user-456');

      await expect(service.refreshTokens(mockPayload)).rejects.toThrow(
        ForbiddenException,
      );

      expect(redisService.del).not.toHaveBeenCalled();
      expect(usersService.findOneById).not.toHaveBeenCalled();
    });
  });
});
