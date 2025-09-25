import { registerAs } from '@nestjs/config';
import { JwtSignOptions } from '@nestjs/jwt';

export default registerAs(
  'accessTokenJwt',
  (): JwtSignOptions => ({
    secret: process.env.SECRET_KEY_JWT,
    expiresIn: process.env.JWT_EXPIRES_IN,
  }),
);
