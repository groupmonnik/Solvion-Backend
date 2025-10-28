import { ResponseType } from '@/common/types/response.type';
import { ArgumentsHost, Catch, ExceptionFilter, HttpStatus, Logger } from '@nestjs/common';
import { FastifyReply } from 'fastify';
import { AuthorizationCodeError } from 'simple-oauth2';

@Catch(AuthorizationCodeError)
export class MetaExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(MetaExceptionFilter.name);

  private red(text: string): string {
    return `\x1b[31m${text}\x1b[0m`;
  }

  catch(exception: AuthorizationCodeError, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<FastifyReply>();
    const details = exception.data || exception.output?.payload || null;

    this.logger.log(this.red(`Mensagem do erro: ${exception.message}`));
    if (details) {
      this.logger.log(this.red(`Dados do erro: ${JSON.stringify(details, null, 2)}`));
    }

    const status =
      (exception.statusCode as number) || HttpStatus.UNAUTHORIZED || HttpStatus.BAD_GATEWAY;

    const message = exception.message || 'Falha na integração com a Meta (OAuth2).';

    response.status(status).send({
      statusCode: status,
      message,
      success: false,
      data: details,
    } as ResponseType<any>);
  }
}
