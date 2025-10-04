import { IsPublic } from '@/common/decorators/public.decorator';
import { Controller, Get, HttpStatus, Query, Res } from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { GoogleAccountsService } from './google-accounts.service';
import { RedirectResponse } from './types/controller/responses/redirect-response';

@Controller('google/accounts')
export class GoogleAccountsController {
  constructor(private readonly googleAccountsService: GoogleAccountsService) {}

  @IsPublic()
  @Get('login')
  handleLogin(@Res() res: FastifyReply) {
    const url = this.googleAccountsService.getAuthUrl();
    res.redirect(url, 302);
  }

  @IsPublic()
  @Get('redirect')
  async handleRedirect(@Query('code') code: string): Promise<RedirectResponse> {
    const tokens = await this.googleAccountsService.getTokens(code);
    const tokenId = this.googleAccountsService.decodeToken(tokens.id_token);
    console.log('Google OAuth2', tokens);
    console.log('__________________________________________________________');
    console.log('Token id', tokenId);

    return {
      statusCode: HttpStatus.OK,
      message: '',
      success: true,
      data: null,
    };
  }
}
