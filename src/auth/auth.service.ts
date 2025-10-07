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

  /**
   * Gera tokens de acesso (access token) e atualização (refresh token) para um usuário.
   *
   * @param {GenerateTokenPayload} payload - Dados necessários para gerar os tokens.
   *   @property {string} payload.email - Email do usuário.
   *   @property {string} [payload.password] - Senha do usuário (necessária se não for refresh token).
   *   @property {boolean} [payload.isRefresh=false] - Indica se a geração é apenas de refresh token.
   *
   * @returns {Promise<{ accessToken: string, refreshToken: string }>} Um objeto contendo:
   *   - `accessToken`: token de acesso criptografado.
   *   - `refreshToken`: token de atualização criptografado.
   *
   * @throws {HttpExceptionCustom} Lança uma exceção se:
   *   - O usuário não for encontrado (`HttpStatus.NOT_FOUND`).
   *   - A senha fornecida estiver incorreta (`HttpStatus.UNAUTHORIZED`), quando aplicável.
   */
  async generateTokens(payload: GenerateTokenPayload) {
    const user = await this.userRepository.findOne({
      where: { email: payload.email },
    });

    if (!user) {
      throw new HttpExceptionCustom(null, HttpStatus.NOT_FOUND, 'User not found');
    }

    if (!payload.isRefresh) {
      const isPasswordValid = await PasswordService.verifyPassword(
        payload.password!,
        user.password,
      );
      if (!isPasswordValid) {
        throw new HttpExceptionCustom(null, HttpStatus.UNAUTHORIZED, 'Password is incorrect');
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
    const decryptedRefresh = this.encryptService.decrypt(refreshToken);

    const user = await this.verifyToken({ token: decryptedRefresh, isRefresh: true });

    if (!user) {
      throw new HttpExceptionCustom(null, HttpStatus.UNAUTHORIZED, 'Invalid refresh token');
    }

    return this.generateTokens({
      email: user.email,
      password: user.password,
      isRefresh: true,
    });
  }

  async verifyToken(payload: VerifyTokenPayload) {
    const decoded = this.jwtService.verify<JwtPayload>(payload.token, {
      secret: payload.isRefresh
        ? this.refreshTokenConfiguration.secret
        : this.accessTokenConfiguration.secret,
    });

    const user = await this.userRepository.findOne({
      where: { id: decoded.sub ?? -1 },
    });

    return user;
  }
}
