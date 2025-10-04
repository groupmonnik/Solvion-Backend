import { HttpStatus, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { URLSearchParams } from 'url';
import axios, { AxiosError } from 'axios';
import { GoogleTokensResponse } from './types/service/return/google-tokens-response-return';
import { decode } from 'jsonwebtoken';
import { HttpExceptionCustom } from '@/common/exceptions/custom/custom.exception';
import { GoogleTokenIdResponse } from './types/service/return/google-tokens-id-response-return';

@Injectable()
export class GoogleAccountsService {
  // * Variaveis de configuração do Google OAuth2
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly redirectUri: string;
  private readonly tokenUri: string;

  constructor(private readonly configService: ConfigService) {
    this.clientId = this.configService.get<string>('GOOGLE_CLIENT_ID')!;
    this.clientSecret = this.configService.get<string>('GOOGLE_CLIENT_SECRET')!;
    this.redirectUri = this.configService.get<string>('GOOGLE_REDIRECT_URI')!;
    this.tokenUri = this.configService.get<string>('GOOGLE_TOKEN_URI')!;
  }

  // * Gera a URL que o usuario deve acessar para autorizar a aplicação
  getAuthUrl(): string {
    // * Escopos da aplicação, isso pode variar dependendo das informação que iremos necessitar
    const scope = ['openid', 'email', 'profile', 'https://www.googleapis.com/auth/adwords'].join(
      ' ',
    );
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope,
      access_type: 'offline', // * Permite refresh_token
      prompt: 'select_account', // * Pede para o usuário selecionar a conta
    });

    return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
  }

  // * Troca o codigo de autorização por tokens
  async getTokens(code: string): Promise<GoogleTokensResponse> {
    const payload = new URLSearchParams({
      code,
      client_id: this.clientId,
      client_secret: this.clientSecret,
      redirect_uri: this.redirectUri,
      grant_type: 'authorization_code',
    });

    try {
      const response = await axios.post<GoogleTokensResponse>(this.tokenUri, payload.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      });

      return response.data;
    } catch (error) {
      const axiosError = error as AxiosError;

      if (axiosError.response) {
        throw new HttpExceptionCustom(
          axiosError.response.data as object,
          axiosError.status,
          'Falha na troca de código por tokens com o Google. Parâmetros inválidos.',
        );
      }
      throw new HttpExceptionCustom(
        null,
        HttpStatus.INTERNAL_SERVER_ERROR,
        'Erro de rede ou infraestrutura ao tentar a comunicação com o Google.',
      );
    }
  }

  // * função expecifica para o token_id onde ele faz um decode para trazer as informações
  decodeToken(tokenId: string) {
    const decodeTokenId = decode(tokenId) as GoogleTokenIdResponse;

    if (!decodeTokenId) {
      throw new HttpExceptionCustom(
        null,
        HttpStatus.BAD_REQUEST,
        'Invalid ID token: could not decode',
      );
    }

    // * objeto com os dados, caso haja necessidade apenas retire os dados que não seram utilizados
    const googleTokenIdResponse: GoogleTokenIdResponse = {
      iss: decodeTokenId.iss,
      aud: decodeTokenId.aud,
      azp: decodeTokenId.azp,
      sub: decodeTokenId.sub,
      email: decodeTokenId.email,
      email_verified: decodeTokenId.email_verified,
      name: decodeTokenId.name,
      picture: decodeTokenId.picture,
      given_name: decodeTokenId.given_name,
      family_name: decodeTokenId.family_name,
      locale: decodeTokenId.locale,
      iat: decodeTokenId.iat,
      exp: decodeTokenId.exp,
    };

    return googleTokenIdResponse;
  }
}
