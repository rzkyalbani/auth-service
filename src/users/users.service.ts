import { Injectable } from '@nestjs/common';
import { Prisma, User } from 'generated/prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  async create(data: Prisma.UserCreateInput) {
    return this.prisma.user.create({
      data,
    });
  }

  async findOneByEmail(email: string): Promise<User | null> {
    return this.prisma.user.findUnique({
      where: { email },
    });
  }

  async findOneById(id: string): Promise<User | null> {
    return this.prisma.user.findUnique({
      where: { id },
    });
  }

  async updateEmailVerified(id: string): Promise<User> {
    return this.prisma.user.update({
      where: { id },
      data: { emailVerifiedAt: new Date() },
    });
  }

  async updateRegistrationData(
    id: string,
    data: { displayName: string; passwordHash: string },
  ): Promise<User> {
    return this.prisma.user.update({
      where: { id },
      data: {
        displayName: data.displayName,
        passwordHash: data.passwordHash,
        emailVerifiedAt: null,
      },
    });
  }

  async updatePassword(id: string, passwordHash: string): Promise<User> {
    return this.prisma.user.update({
      where: { id },
      data: { passwordHash: passwordHash },
    });
  }
}
