import { CanActivate, ExecutionContext, HttpStatus, Injectable } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Reflector } from '@nestjs/core';
import { HttpExceptionCustom } from '@/common/exceptions/custom/custom.exception';
import { FastifyRequest } from 'fastify';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private authService: AuthService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const IsPublic = this.reflector.getAllAndOverride<boolean>('IsPublic', [
      context.getHandler(),
      context.getClass(),
    ]);

    if (IsPublic) {
      return true;
    }

    const request = context.switchToHttp().getRequest<FastifyRequest>();
    const authHeader = request.headers['authorization'];

    if (!authHeader) {
      throw new HttpExceptionCustom(null, HttpStatus.UNAUTHORIZED, 'No token provided');
    }

    const token = authHeader.split(' ')[1];

    try {
      await this.authService.verify(token);
    } catch {
      throw new HttpExceptionCustom(null, HttpStatus.UNAUTHORIZED, 'invalid token');
    }

    return true;
  }
}
