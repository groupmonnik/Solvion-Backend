import { HttpExceptionCustom } from '@/common/exceptions/custom/custom.exception';
import { HttpStatus, Inject, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '@/users/entities/user.entity';
import { EncryptService } from '@/common/encrypt/encrypt.service.auth';
import accessTokenJwtConfig from './config/access-token-jwt.config';
import * as config from '@nestjs/config';
import refreshTokenJwtConfig from './config/refresh-token-jwt.config';
import { PasswordService } from '@/common/encrypt/password.service';
import { GenerateTokenPayload } from './types/service/payloads/generate-token-payload.type';
import { VerifyTokenPayload } from './types/service/payloads/verify-token-payload.type';
import { JwtPayload } from './types/service/payloads/jwt-payload.type';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly jwtService: JwtService,
    private readonly encryptService: EncryptService,
    @Inject(accessTokenJwtConfig.KEY)
    private readonly accessTokenConfiguration: config.ConfigType<typeof accessTokenJwtConfig>,
    @Inject(refreshTokenJwtConfig.KEY)
    private readonly refreshTokenConfiguration: config.ConfigType<typeof refreshTokenJwtConfig>,
  ) {}

  async generateTokens(payload: GenerateTokenPayload) {
    const user = await this.userRepository.findOne({
      where: { email: payload.email },
    });

    if (!user) {
      throw new HttpExceptionCustom(null, HttpStatus.NOT_FOUND, 'user not found');
    }

    if (!payload.isRefresh) {
      if (!payload.password) {
        throw new HttpExceptionCustom(null, HttpStatus.BAD_REQUEST, 'Password is required');
      }

      const isPasswordValid = await PasswordService.verifyPassword(payload.password, user.password);
      if (!isPasswordValid) {
        throw new HttpExceptionCustom(null, HttpStatus.BAD_REQUEST, 'Password is incorrect');
      }
    }

    const accessPayload = { sub: user.id, email: user.email };
    const rawAccessToken = this.jwtService.sign(accessPayload, this.accessTokenConfiguration);

    const refreshPayload = { sub: user.id };
    const rawRefreshToken = this.jwtService.sign(refreshPayload, this.refreshTokenConfiguration);

    const accessToken = this.encryptService.encrypt(rawAccessToken);
    const refreshToken = this.encryptService.encrypt(rawRefreshToken);

    return { accessToken, refreshToken };
  }

  async refreshToken(refreshToken: string) {
    try {
      const decryptedRefresh = this.encryptService.decrypt(refreshToken);

      const user = await this.verifyToken({ token: decryptedRefresh, isRefresh: true });

      if (!user) {
        throw new HttpExceptionCustom(null, HttpStatus.UNAUTHORIZED, 'invalid refresh token');
      }

      return this.generateTokens({
        email: user.email,
        password: user.password,
        isRefresh: true,
      });
    } catch (error) {
      if (error instanceof HttpExceptionCustom) {
        throw error;
      }
      throw new HttpExceptionCustom({ error }, HttpStatus.UNAUTHORIZED, 'Invalid refresh token');
    }
  }

  async verifyToken(payload: VerifyTokenPayload) {
    try {
      const decoded = this.jwtService.verify<JwtPayload>(payload.token, {
        secret: payload.isRefresh
          ? this.refreshTokenConfiguration.secret
          : this.accessTokenConfiguration.secret,
      });

      const user = await this.userRepository.findOne({
        where: { id: decoded.sub ?? -1 },
      });

      return user;
    } catch (error) {
      if (error instanceof HttpExceptionCustom) {
        throw error;
      }
      throw new HttpExceptionCustom(
        { error },
        HttpStatus.INTERNAL_SERVER_ERROR,
        'Internal Server Error',
      );
    }
  }
}
