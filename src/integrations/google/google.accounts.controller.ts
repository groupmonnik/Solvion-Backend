import { IsPublic } from "@/common/decorators/public.decorator";
import { Controller, Get, HttpStatus, Query, Res } from "@nestjs/common";
import type { FastifyReply } from "fastify";
import { GoogleAccountsService } from "./google.accounts.service";
import { RedirectResponse } from "./types/controller/responses/redirect.response";

@Controller("google/accounts")
export class GoogleAccountsController {
  constructor(private readonly googleAccountsService: GoogleAccountsService) {}

  @IsPublic()
  @Get("login")
  handleLogin(@Res() res: FastifyReply) {
    const url = this.googleAccountsService.getAuthUrl();
    res.redirect(url, 302);
  }

  @Get("redirect")
  async handleRedirect(@Query("code") code: string): Promise<RedirectResponse> {
    const tokens = await this.googleAccountsService.getTokens(code);
    const tokenId = await this.googleAccountsService.decodeToken(
      tokens.id_token!,
    );

    return {
      statusCode: HttpStatus.OK,
      message: "redirection and collection of tokens done successfully",
      success: true,
      data: null,
    };
  }
}
