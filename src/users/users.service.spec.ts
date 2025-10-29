import { Test, TestingModule } from '@nestjs/testing';
import { UsersService } from './users.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { User } from 'generated/prisma/client';

const mockUser: User = {
  id: 'clx123456',
  email: 'test@example.com',
  passwordHash: 'hashedpassword123',
  displayName: 'Test User',
  emailVerifiedAt: null,
  provider: 'LOCAL',
  twoFAEnabled: false,
  twoFASecretEnc: null,
  createdAt: new Date(),
  updatedAt: new Date(),
};

const mockPrismaService = {
  user: {
    create: jest.fn().mockResolvedValue(mockUser),
    findUnique: jest.fn().mockResolvedValue(mockUser),
  },
};

describe('UsersService', () => {
  let service: UsersService;
  let prisma: PrismaService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsersService,
        {
          provide: PrismaService,
          useValue: mockPrismaService,
        },
      ],
    }).compile();

    service = module.get<UsersService>(UsersService);
    prisma = module.get<PrismaService>(PrismaService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('create', () => {
    it('should create a new user', async () => {
      const createUserData = {
        email: 'test@example.com',
        passwordHash: 'hashedpassword123',
        displayName: 'Test User',
      };

      const result = await service.create(createUserData);

      expect(prisma.user.create).toHaveBeenCalledWith({
        data: createUserData,
      });

      expect(result).toEqual(mockUser);
    });
  });

  describe('findOneByEmail', () => {
    it('should return a user if found', async () => {
      const email = 'test@example.com';

      const result = await service.findOneByEmail(email);

      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { email },
      });

      expect(result).toEqual(mockUser);
    });

    it('should return null if user not found', async () => {
      jest.spyOn(prisma.user, 'findUnique').mockResolvedValue(null);

      const email = 'notfound@example.com';
      const result = await service.findOneByEmail(email);

      expect(result).toBeNull();
    });
  });
});
