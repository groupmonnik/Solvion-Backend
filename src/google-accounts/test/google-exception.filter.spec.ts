import { GoogleExceptionFilter } from '@/common/exception-filters/http-exception/google-exception.filter';
import { ResponseType } from '@/common/types/response.type';
import { ArgumentsHost, HttpStatus, Logger } from '@nestjs/common';
import { FastifyReply, FastifyRequest } from 'fastify';
import { GaxiosError } from 'gaxios';

describe('GoogleExceptionFilter', () => {
  let filter: GoogleExceptionFilter;
  let mockResponse: Partial<FastifyReply>;
  let mockRequest: Partial<FastifyRequest>;
  let mockHost: Partial<ArgumentsHost>;

  beforeEach(() => {
    filter = new GoogleExceptionFilter();

    mockResponse = {
      status: jest.fn().mockReturnThis(),
      send: jest.fn(),
    };

    mockRequest = {
      method: 'GET',
      url: '/test-route',
    };

    mockHost = {
      switchToHttp: jest.fn().mockReturnValue({
        getResponse: () => mockResponse,
        getRequest: () => mockRequest,
      }),
    };

    jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('deve capturar qualquer erro GaxiosError e enviar uma resposta com detalhes', () => {
    const fakeResponse = {
      status: 400,
      data: { error_description: 'Falha na requisição Google' },
      headers: {},
      config: {},
    } as any;

    const exception = new GaxiosError('Erro de teste1', {} as any, {} as any, fakeResponse);

    (exception as any).response = fakeResponse;

    filter.catch(exception, mockHost as ArgumentsHost);

    expect(Logger.prototype.log).toHaveBeenCalledWith(
      expect.stringContaining('Mensagem do erro: Erro de teste1'),
    );
    expect(Logger.prototype.log).toHaveBeenCalledWith(expect.stringContaining('Dados de erro:'));

    expect(mockResponse.status).toHaveBeenCalledWith(400);
    expect(mockResponse.send).toHaveBeenCalledWith({
      statusCode: 400,
      message: 'Erro de teste1',
      success: false,
      data: fakeResponse,
    } as ResponseType<any>);
  });

  it('deve usar valores padrão caso não exista resposta do Google', () => {
    const exception = new GaxiosError('Erro sem response', {} as any, {} as any, undefined);

    filter.catch(exception, mockHost as ArgumentsHost);

    expect(mockResponse.status).toHaveBeenCalledWith(HttpStatus.BAD_REQUEST);
    expect(mockResponse.send).toHaveBeenCalledWith({
      statusCode: HttpStatus.BAD_REQUEST,
      message: 'Erro sem response',
      success: false,
      data: {
        config: {},
        data: undefined,
      },
    });
  });
});
