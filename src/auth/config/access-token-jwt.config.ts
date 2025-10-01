import { registerAs } from '@nestjs/config';
import { JwtSignOptions } from '@nestjs/jwt';

export default registerAs('accessTokenJwt', (): JwtSignOptions => {
  if (!process.env.ACCESS_TOKEN_JWT_KEY || !process.env.ACCESS_TOKEN_JWT_EXPIRES_IN) {
    throw new Error('Missing environment variables for access token configuration');
  }

  return {
    secret: process.env.ACCESS_TOKEN_JWT_KEY,
    expiresIn: process.env.ACCESS_TOKEN_JWT_EXPIRES_IN,
  };
});
