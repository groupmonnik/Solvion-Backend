import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuthorizationCode } from 'simple-oauth2';
import { GetToken } from './types/service/return/get.token.return';

@Injectable()
export class MetaAuthService {
  private client: AuthorizationCode;
  constructor(private readonly configService: ConfigService) {
    this.client = new AuthorizationCode({
      client: {
        id: configService.get<string>('FB_APP_ID'),
        secret: configService.get<string>('FB_APP_SECRET'),
      },
      auth: {
        tokenHost: 'https://graph.facebook.com',
        tokenPath: '/v24.0/oauth/access_token',
        authorizeHost: 'https://www.facebook.com',
        authorizePath: '/v24.0/dialog/oauth',
      },
    });
  }

  getAuthUrl(): string {
    return this.client.authorizeURL({
      redirect_uri: this.configService.get<string>('FB_REDIRECT_URI'),
      scope: this.configService.get<string>('FB_SCOPES'),
      response_type: 'code',
      auth_type: 'reauthenticate',
    }) as string;
  }

  async getTokens(code: string): Promise<GetToken> {
    const tokenParams = {
      code,
      redirect_uri: this.configService.get<string>('FB_REDIRECT_URI'),
    };
    const accessToken = await this.client.getToken(tokenParams);

    return {
      token: accessToken.token.access_token,
      expires_at: new Date(accessToken.token.expires_at),
    };
  }
}
