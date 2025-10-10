import { FastifyRequest } from 'fastify';
import { Profile } from 'passport-google-oauth20';

export type GoogleRequest = FastifyRequest & {
  user: {
    accessToken: string;
    refreshToken: string;
    profile: Profile;
  };
};
