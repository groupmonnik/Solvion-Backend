import { registerAs } from '@nestjs/config';
import { JwtSignOptions } from '@nestjs/jwt';

export default registerAs('refreshTokenJwt', (): JwtSignOptions => {
  if (!process.env.REFRESH_TOKEN_JWT_KEY || !process.env.REFRESH_TOKEN_JWT_EXPIRES_IN) {
    throw new Error('Missing environment variables for refresh token configuration');
  }

  return {
    secret: process.env.REFRESH_TOKEN_JWT_KEY,
    expiresIn: process.env.REFRESH_TOKEN_JWT_EXPIRES_IN,
  };
});
