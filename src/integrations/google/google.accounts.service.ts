import { HttpExceptionCustom } from "@/common/exceptions/custom/custom.exception";
import { HttpStatus, Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { google, Auth } from "googleapis";

@Injectable()
export class GoogleAccountsService {
  private oauth2Client: Auth.OAuth2Client;

  constructor(private readonly configService: ConfigService) {
    this.oauth2Client = new google.auth.OAuth2(
      this.configService.get<string>("GOOGLE_CLIENT_ID"),
      this.configService.get<string>("GOOGLE_CLIENT_SECRET"),
      this.configService.get<string>("GOOGLE_REDIRECT_URI"),
    );
  }

  getAuthUrl(): string {
    return this.oauth2Client.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      scope: [
        "openid",
        "email",
        "profile",
        "https://www.googleapis.com/auth/adwords",
      ],
    });
  }

  async getTokens(code: string): Promise<Auth.Credentials> {
    const token = await this.oauth2Client.getToken(code);
    return token.tokens;
  }

  async decodeToken(tokenId: string): Promise<Auth.TokenPayload> {
    const token = await this.oauth2Client.verifyIdToken({
      idToken: tokenId,
      audience: this.configService.get<string>("GOOGLE_CLIENT_ID"),
    });

    const payload = token.getPayload()!;
    if (!payload) {
      throw new HttpExceptionCustom(
        null,
        HttpStatus.BAD_REQUEST,
        "Invalid ID token: could not decode",
      );
    }

    return payload;
  }
}
