import { HttpExceptionCustom } from '@/common/exceptions/custom/custom.exception';
import { HttpStatus, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { google, Auth } from 'googleapis';

@Injectable()
export class GoogleAccountsService {
  // * Variaveis de configuração do Google OAuth2
  private oauth2Client: Auth.OAuth2Client;

  constructor(private readonly configService: ConfigService) {
    this.oauth2Client = new google.auth.OAuth2(
      this.configService.get<string>('GOOGLE_CLIENT_ID'),
      this.configService.get<string>('GOOGLE_CLIENT_SECRET'),
      this.configService.get<string>('GOOGLE_REDIRECT_URI'),
    );
  }

  // * Gera a URL que o usuario deve acessar para autorizar a aplicação
  getAuthUrl(): string {
    return this.oauth2Client.generateAuthUrl({
      access_type: 'offline',
      prompt: 'consent',
      scope: ['openid', 'email', 'profile', 'https://www.googleapis.com/auth/adwords'],
    });
  }

  // * Troca o codigo de autorização por tokens
  async getTokens(code: string): Promise<Auth.Credentials> {
    const token = await this.oauth2Client.getToken(code);
    return token.tokens;
  }

  /**
   * Decodifica um ID token do Google e retorna o payload do token.
   *
   * @param {string} tokenId - O ID token do Google a ser verificado e decodificado.
   * @returns {Promise<Auth.TokenPayload>} Uma Promise que resolve para o payload do token,
   * incluindo informações do usuário, como email, nome e ID do Google.
   *
   * @throws {Error} Lança um erro se o token for inválido ou não puder ser verificado.
   */
  async decodeToken(tokenId: string): Promise<Auth.TokenPayload> {
    const token = await this.oauth2Client.verifyIdToken({
      idToken: tokenId,
      audience: this.configService.get<string>('GOOGLE_CLIENT_ID'),
    });

    return token.getPayload()!;
  }

  async refreshAccessToken(refreshToken: string) {
    this.oauth2Client.setCredentials({ refresh_token: refreshToken });
    const tokenResponse = await this.oauth2Client.getAccessToken();
    if (!tokenResponse) {
      throw new HttpExceptionCustom(null, HttpStatus.BAD_REQUEST, 'deu ruim aqui!');
    }
    return {
      access_token: tokenResponse.token,
      expiry_date: this.oauth2Client.credentials.expiry_date,
    };
  }
}
