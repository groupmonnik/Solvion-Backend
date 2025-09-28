import { Injectable, UnauthorizedException, Inject } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-jwt';
import { FastifyRequest } from 'fastify';
import * as config from '@nestjs/config';
import accessTokenConfig from '@/auth/config/access-token-jwt.config';
import { EncryptService } from '@/common/encrypt/encrypt.service.auth';
import { JwtPayload } from '../service/payload/jwt-payload.type';

@Injectable()
export class AccessTokenJwtStrategy extends PassportStrategy(Strategy, 'AccessTokenJwt') {
  constructor(
    @Inject(accessTokenConfig.KEY)
    private readonly accessTokenConfiguration: config.ConfigType<typeof accessTokenConfig>,
    private readonly encryptService: EncryptService,
  ) {
    super({
      jwtFromRequest: (req: FastifyRequest): string | null => {
        const cookies = req.cookies as { accessToken?: string };
        const encryptedFromCookie = cookies?.accessToken;

        const authHeader = req.headers['authorization'];
        const encryptedFromHeader = authHeader?.startsWith('Bearer ')
          ? authHeader.split(' ')[1]
          : null;

        if (!encryptedFromCookie && !encryptedFromHeader) {
          throw new UnauthorizedException('Token not provided');
        }

        const encryptedToken = encryptedFromCookie ?? encryptedFromHeader;

        try {
          return encryptService.decrypt(encryptedToken!);
        } catch {
          throw new UnauthorizedException('Invalid encrypted token');
        }
      },
      secretOrKey: accessTokenConfiguration.secret,
      ignoreExpiration: false,
    });
  }

  validate(payload: JwtPayload): Promise<JwtPayload> {
    if (!payload?.sub) {
      throw new UnauthorizedException('Invalid payload');
    }
    return Promise.resolve(payload);
  }
}
