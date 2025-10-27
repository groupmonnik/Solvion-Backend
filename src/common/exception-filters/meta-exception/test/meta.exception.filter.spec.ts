import { MetaExceptionFilter } from '@/common/exception-filters/meta-exception/meta.exception.filter';
import { FastifyReply } from 'fastify';
import { ArgumentsHost, HttpStatus } from '@nestjs/common';

describe('MetaExceptionFilter', () => {
  let filter: MetaExceptionFilter;
  let mockReply: Partial<FastifyReply>;
  let mockHost: Partial<ArgumentsHost>;

  beforeEach(() => {
    filter = new MetaExceptionFilter();

    mockReply = {
      status: jest.fn().mockReturnThis(),
      send: jest.fn(),
    };

    mockHost = {
      switchToHttp: jest.fn().mockReturnValue({
        getResponse: () => mockReply,
      }),
    };
  });

  it('deve capturar erro OAuth2 simulado e retornar resposta formatada', () => {
    const exception = {
      name: 'AuthorizationCodeError',
      message: 'invalid_grant',
      statusCode: 401,
      data: {
        error: 'invalid_grant',
        error_description: 'Código inválido',
      },
    } as any;

    filter.catch(exception, mockHost as ArgumentsHost);

    expect(mockReply.status).toHaveBeenCalledWith(HttpStatus.UNAUTHORIZED);
    expect(mockReply.send).toHaveBeenCalledWith(
      expect.objectContaining({
        statusCode: HttpStatus.UNAUTHORIZED,
        message: 'invalid_grant',
        success: false,
        data: expect.objectContaining({
          error: 'invalid_grant',
        }),
      }),
    );
  });

  it('deve lidar com erro sem data (detalhes nulos)', () => {
    const exception = {
      name: 'AuthorizationCodeError',
      message: 'server_error',
    } as any;

    filter.catch(exception, mockHost as ArgumentsHost);

    expect(mockReply.status).toHaveBeenCalledWith(HttpStatus.UNAUTHORIZED);
    expect(mockReply.send).toHaveBeenCalledWith(
      expect.objectContaining({
        statusCode: HttpStatus.UNAUTHORIZED,
        message: 'server_error',
        success: false,
      }),
    );
  });

  it('deve registrar logs de erro', () => {
    const mockLogger = { log: jest.fn(), error: jest.fn() };
    (filter as any).logger = mockLogger;

    const exception = {
      name: 'AuthorizationCodeError',
      message: 'invalid_client',
      statusCode: 401,
      data: { error: 'invalid_client' },
    } as any;

    filter.catch(exception, mockHost as ArgumentsHost);

    expect(mockLogger.log).toHaveBeenCalled();
  });
});
