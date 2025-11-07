// src/auth/strategies/google.strategy.ts
import { PassportStrategy } from '@nestjs/passport';
import {
  OAuth2StrategyOptionsWithoutRequiredURLs,
  Strategy,
  VerifyCallback,
} from 'passport-google-oauth20';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuthService } from '../auth.service';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    configService: ConfigService,
    private authService: AuthService,
  ) {
    super({
      clientID: configService.get<string>('GOOGLE_CLIENT_ID'),
      clientSecret: configService.get<string>('GOOGLE_CLIENT_SECRET'),
      callbackURL: configService.get<string>('GOOGLE_CALLBACK_URL'),
      scope: ['email', 'profile'],
    } as OAuth2StrategyOptionsWithoutRequiredURLs);
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<any> {
    const { id, name, emails, photos } = profile;

    const userProfile = {
      provider: 'GOOGLE',
      providerId: id,
      email: emails[0].value,
      displayName: name.givenName || name.familyName,
      picture: photos[0].value,
    };

    try {
      const user = await this.authService.validateOAuthUser(userProfile);

      done(null, user);
    } catch (error) {
      done(error, false);
    }
  }
}
