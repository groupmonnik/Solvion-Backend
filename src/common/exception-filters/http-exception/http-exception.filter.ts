import { ExceptionResponseType } from '@/common/exception-filters/http-exception/types/exception-response.type';
import { ResponseType } from '@/common/types/response.type';
import { ArgumentsHost, Catch, ExceptionFilter, HttpException } from '@nestjs/common';
import { FastifyReply } from 'fastify';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<FastifyReply>();
    const status = exception.getStatus();
    const exceptionResponse = exception.getResponse() as ExceptionResponseType;

    // Log the exception details to the console for debugging
    console.log('\n\n======================================================================\n\n');
    console.log('Exception: ', exceptionResponse);

    response.status(status).send({
      statusCode: status,
      success: false,
      message: exception.message ?? 'An error occurred',
      data: Object.keys(exceptionResponse.data ?? {}).length ? exceptionResponse.data : null,
    } as ResponseType<any>);
  }
}
