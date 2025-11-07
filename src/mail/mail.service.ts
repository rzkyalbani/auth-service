import { MailerService } from '@nestjs-modules/mailer';
import { Injectable } from '@nestjs/common';
import { User } from 'generated/prisma/client';


@Injectable()
export class MailService {
  constructor(private mailerService: MailerService) {}

  async sendUserVerification(user: User, token: string) {
    const verificationUrl = `http://localhost:3000/auth/verify-email?token=${token}`;

    await this.mailerService.sendMail({
      to: user.email,
      subject: 'Selamat Datang! Verifikasi Email Kamu',
      template: './email-verification', 
      context: {
        displayName: user.displayName,
        verificationUrl: verificationUrl,
      },
    });
  }
}