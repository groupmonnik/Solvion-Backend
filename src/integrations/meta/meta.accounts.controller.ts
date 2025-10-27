import { IsPublic } from "@/common/decorators/public.decorator";
import { MetaAuthService } from "@/integrations/meta/meta.accounts.service";
import {
  Controller,
  Get,
  HttpStatus,
  Query,
  Res,
  UnauthorizedException,
} from "@nestjs/common";
import type { FastifyReply } from "fastify";
import { RedirectResponse } from "./types/controller/responses/redirect.response";

@Controller("meta/accounts")
export class MetaAuthController {
  constructor(private readonly metaAuthService: MetaAuthService) {}

  @IsPublic()
  @Get("login")
  redirectToMeta(@Res() res: FastifyReply) {
    const url = this.metaAuthService.getAuthUrl();
    return res.redirect(url, 302);
  }

  @IsPublic()
  @Get("redirect")
  async metaCallback(@Query("code") code: string): Promise<RedirectResponse> {
    if (!code) {
      throw new UnauthorizedException(
        "Código de autorização ausente ou inválido",
      );
    }
    const tokens = await this.metaAuthService.getTokens(code);
    console.log(tokens);
    return {
      statusCode: HttpStatus.OK,
      message: "redirection and collection of tokens done successfully",
      success: true,
      data: null,
    };
  }
}
