import { Body, Controller, HttpCode, HttpStatus, Post, Req, Res } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBody, ApiCookieAuth } from '@nestjs/swagger';
import { LoginDto } from './dto/login-auth.dto';
import { AuthService } from './auth.service';
import { IsPublic } from '@/common/decorators/public.decorator';
import type { FastifyReply, FastifyRequest } from 'fastify';
import dayjs from 'dayjs';
import duration from 'dayjs/plugin/duration';
import { clearAuthCookie, setAuthCookie } from '@/common/utils/cookies.util';
import { LoginResponse } from './types/controller/responses/login-response.type';
import { RefreshResponse } from './types/controller/responses/refresh-response.type';
import type { LogoutResponse } from './types/controller/responses/logout-response.type';

dayjs.extend(duration);

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @IsPublic()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'User login' })
  @ApiBody({ type: LoginDto })
  @ApiResponse({
    status: 200,
    description: 'Login successful',
    schema: { example: { accessToken: 'jwt_token' } },
  })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  async login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) res: FastifyReply,
  ): Promise<LoginResponse> {
    const { accessToken, refreshToken } = await this.authService.generateTokens(loginDto);

    setAuthCookie(res, accessToken, refreshToken);

    return {
      statusCode: HttpStatus.OK,
      message: 'login successfully',
      success: true,
      data: null,
    };
  }

  @IsPublic()
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Renew access token using refresh token' })
  @ApiCookieAuth()
  @ApiResponse({
    status: 200,
    description: 'New accessToken generated',
    schema: { example: { accessToken: 'jwt_token' } },
  })
  @ApiResponse({ status: 401, description: 'Missing or Invalid refresh token' })
  async refresh(
    @Req() req: FastifyRequest,
    @Res({ passthrough: true }) res: FastifyReply,
  ): Promise<RefreshResponse> {
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
      res.status(HttpStatus.UNAUTHORIZED);

      return {
        statusCode: HttpStatus.UNAUTHORIZED,
        message: 'No refresh token provided',
        success: false,
        data: null,
      };
    }

    const unsigned = req.unsignCookie(refreshToken);
    if (!unsigned.valid || !unsigned.value) {
      res.status(HttpStatus.UNAUTHORIZED);

      return {
        statusCode: HttpStatus.UNAUTHORIZED,
        message: 'Invalid refresh token signature',
        success: false,
        data: null,
      };
    }

    const { accessToken, refreshToken: newRefreshToken } = await this.authService.refreshToken(
      unsigned.value,
    );

    setAuthCookie(res, accessToken, newRefreshToken);

    return {
      statusCode: HttpStatus.OK,
      message: 'New tokens generated',
      success: true,
      data: null,
    };
  }

  @IsPublic()
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'User logout' })
  @ApiCookieAuth()
  @ApiResponse({
    status: 200,
    description: 'Logout successful',
    schema: { example: { message: 'Logged out successfully' } },
  })
  logout(@Res({ passthrough: true }) res: FastifyReply): LogoutResponse {
    clearAuthCookie(res);
    return {
      statusCode: HttpStatus.OK,
      message: 'Logged out successfully',
      success: true,
      data: null,
    };
  }
}
