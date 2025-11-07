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

  async sendPasswordReset(user: User, token: string) {
    const resetUrl = `http://localhost:3001/reset-password?token=${token}`;

    await this.mailerService.sendMail({
      to: user.email,
      subject: 'Permintaan Reset Password Kamu',
      template: './password-reset',
      context: {
        displayName: user.displayName,
        resetUrl: resetUrl,
      },
    });
  }
}
