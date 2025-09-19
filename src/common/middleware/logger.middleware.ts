import { Injectable, NestMiddleware, Logger } from '@nestjs/common';
import { FastifyRequest, FastifyReply } from 'fastify';

@Injectable()
export class LoggerMiddleware implements NestMiddleware {
  private logger = new Logger('HTTP');

  use(req: FastifyRequest, reply: FastifyReply, next: () => void) {
    const { ip, method, url } = req;
    const userAgent = req.headers['user-agent'] || '';
    const startTime = Date.now();

    this.logger.log(`${method} ${url} - ${ip} - ${userAgent}`);

    reply.raw.on('finish', () => {
      const statusCode = reply.statusCode;
      const responseTime = Date.now() - startTime;

      this.logger.log(`${method} ${url} ${statusCode} - ${responseTime}ms`);
    });

    next();
  }
}
