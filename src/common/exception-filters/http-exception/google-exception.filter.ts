import { ArgumentsHost, Catch, ExceptionFilter, HttpStatus, Logger } from '@nestjs/common';
import { FastifyReply } from 'fastify';
import { GaxiosError } from 'gaxios';

@Catch(GaxiosError)
export class GoogleExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(GoogleExceptionFilter.name);

  private red(text: string): string {
    return `\x1b[31m${text}\x1b[0m`;
  }

  catch(exception: GaxiosError, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<FastifyReply>();
    const details = exception.response || null;

    this.logger.log(this.red(`Mensagem do erro: ${exception.message}`));
    if (details) {
      this.logger.log(this.red(`Dados de erro: ${JSON.stringify(details, null, 2)}`));
    }

    const status = exception.response?.status ?? HttpStatus.BAD_REQUEST;
    const message = exception.message || 'Erro desconhecido';

    response.status(status).send({
      statusCode: status,
      message,
      error: 'GaxiosError',
      details,
    });
  }
}
