import { FastifyReply } from 'fastify';
import dayjs from 'dayjs';

export function setAuthCookie(res: FastifyReply, accessToken: string, refreshToken: string): void {
  res.setCookie('accessToken', accessToken, {
    httpOnly: true,
    secure: false,
    sameSite: 'strict',
    path: '/',
    maxAge: dayjs.duration(15, 'minute').asMilliseconds(),
  });

  res.setCookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: false,
    path: '/',
    sameSite: 'strict',
    maxAge: dayjs.duration(1, 'day').asMilliseconds(),
  });
}

export function clearAuthCookie(res: FastifyReply): void {
  res.clearCookie('accessToken', {
    httpOnly: true,
    sameSite: 'strict',
    secure: false,
    path: '/',
  });

  res.clearCookie('refreshToken', {
    httpOnly: true,
    sameSite: 'strict',
    secure: false,
    path: '/',
  });
}
