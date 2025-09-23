import { Body, Controller, HttpCode, HttpStatus, Post, Req, Res } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBody, ApiCookieAuth } from '@nestjs/swagger';
import { LoginDto } from './dto/login-auth.dto';
import { AuthService } from './auth.service';
import { IsPublic } from '@/common/decorators/public.decorator';
import type { FastifyReply, FastifyRequest } from 'fastify';
import dayjs from 'dayjs';
import duration from 'dayjs/plugin/duration';

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
  async login(@Body() loginDto: LoginDto, @Res({ passthrough: true }) res: FastifyReply) {
    const { accessToken, refreshToken } = await this.authService.generate(loginDto);

    res.setCookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: false,
      path: '/api/auth/refresh',
      sameSite: 'strict',
      maxAge: dayjs.duration(1, 'day').asMilliseconds(),
    });

    return { accessToken };
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
  @ApiResponse({ status: 401, description: 'Missing or invalid refresh token' })
  async refresh(@Req() req: FastifyRequest, @Res({ passthrough: true }) res: FastifyReply) {
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
      return res.status(HttpStatus.UNAUTHORIZED).send({ message: 'No refresh token provided' });
    }

    const { accessToken, refreshToken: newRefreshToken } =
      await this.authService.refreshToken(refreshToken);

    res.setCookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      sameSite: 'strict',
      secure: false,
      path: '/api/auth/refresh',
    });

    return { accessToken };
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
  logout(@Res({ passthrough: true }) res: FastifyReply) {
    res.clearCookie('refreshToken', {
      httpOnly: true,
      sameSite: 'strict',
      secure: false,
      path: '/api/auth/refresh',
    });

    return { message: 'Logged out successfully' };
  }
}
