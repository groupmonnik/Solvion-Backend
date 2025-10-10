import { Test, TestingModule } from '@nestjs/testing';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import { ValidationPipe, HttpStatus } from '@nestjs/common';
import request from 'supertest';
import { TypeOrmModule } from '@nestjs/typeorm';
import { GoogleAccountsController } from '@/google-accounts/google-accounts.controller';
import { GoogleAccountsService } from '@/google-accounts/google-accounts.service';
import { ConfigService } from '@nestjs/config';
import { User } from '@/users/entities/user.entity';
import { google } from 'googleapis';

jest.mock('googleapis', () => {
  const mVerify = jest.fn();
  const mGetToken = jest.fn();
  const mGenerateAuthUrl = jest.fn(() => 'https://mocked-auth-url.com');

  const mOAuth2 = jest.fn(() => ({
    getToken: mGetToken,
    verifyIdToken: mVerify,
    generateAuthUrl: mGenerateAuthUrl,
  }));

  return {
    google: {
      auth: {
        OAuth2: mOAuth2,
      },
    },
  };
});

describe('GoogleAccountsController (Integration with mocked code)', () => {
  let app: NestFastifyApplication;
  let service: GoogleAccountsService;
  let mockOAuth2Instance: any;

  const mockConfigService = {
    get: (key: string) => {
      const values: Record<string, string> = {
        GOOGLE_CLIENT_ID: 'test-client-id',
        GOOGLE_CLIENT_SECRET: 'test-client-secret',
        GOOGLE_REDIRECT_URI: 'http://localhost/google/redirect',
      };
      return values[key];
    },
  };

  const fakeTokens = {
    access_token: 'mock-access-token',
    expires_in: 3600,
    refresh_token: 'mock-refresh-token',
    scope: 'openid email profile https://www.googleapis.com/auth/adwords',
    token_type: 'Bearer',
    id_token: 'mock-id-token',
  };

  const fakeDecodedToken = {
    iss: 'accounts.google.com',
    aud: 'test-client-id',
    sub: '123456789',
    email: 'test@example.com',
    email_verified: true,
    name: 'Test User',
  };

  beforeAll(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [
        TypeOrmModule.forRoot({
          type: 'sqlite',
          database: ':memory:',
          dropSchema: true,
          entities: [User],
          synchronize: true,
          logging: false,
        }),
        TypeOrmModule.forFeature([User]),
      ],
      controllers: [GoogleAccountsController],
      providers: [GoogleAccountsService, { provide: ConfigService, useValue: mockConfigService }],
    }).compile();

    app = module.createNestApplication<NestFastifyApplication>(new FastifyAdapter());
    app.useGlobalPipes(new ValidationPipe({ whitelist: true }));
    await app.init();
    await app.getHttpAdapter().getInstance().ready();

    service = module.get<GoogleAccountsService>(GoogleAccountsService);

    // capturamos a instância real do OAuth2 mockado
    const { google } = jest.requireMock('googleapis');
    mockOAuth2Instance = new google.auth.OAuth2();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('GET /google/accounts/login', () => {
    it('should call handleLogin and redirect', async () => {
      const response = await request(app.getHttpServer())
        .get('/google/accounts/login')
        .expect(HttpStatus.FOUND);

      expect(response.headers['location']).toBe('https://mocked-auth-url.com');
    });
  });

  describe('GET /google/accounts/redirect', () => {
    it('should handle redirect and return Ok message', async () => {
      mockOAuth2Instance.getToken.mockResolvedValue({ tokens: fakeTokens });
      mockOAuth2Instance.verifyIdToken.mockResolvedValue({
        getPayload: () => fakeDecodedToken,
      });

      const code = 'mocked-code';
      const response = await request(app.getHttpServer())
        .get('/google/accounts/redirect')
        .query({ code })
        .expect(HttpStatus.OK);

      expect(response.body).toEqual({
        statusCode: HttpStatus.OK,
        message: 'redirection and collection of tokens done successfully',
        success: true,
        data: null,
      });

      expect(mockOAuth2Instance.getToken).toHaveBeenCalledWith(code);
      expect(mockOAuth2Instance.verifyIdToken).toHaveBeenCalledWith({
        idToken: 'mock-id-token',
        audience: 'test-client-id',
      });
    });

    it('should return error if getToken fails', async () => {
      mockOAuth2Instance.getToken.mockRejectedValue(new Error('Network Error'));

      const code = 'mocked-code';
      const response = await request(app.getHttpServer())
        .get('/google/accounts/redirect')
        .query({ code });

      expect(response.status).toBe(HttpStatus.INTERNAL_SERVER_ERROR);
      expect(response.body).toHaveProperty('message');
    });

    it('should return error if decode returns null', async () => {
      mockOAuth2Instance.getToken.mockResolvedValue({ tokens: fakeTokens });
      mockOAuth2Instance.verifyIdToken.mockResolvedValue({
        getPayload: () => null,
      });

      const code = 'mocked-code';
      const response = await request(app.getHttpServer())
        .get('/google/accounts/redirect')
        .query({ code })
        .expect(HttpStatus.BAD_REQUEST);

      expect(response.body).toEqual({
        message: 'Invalid ID token: could not decode',
        data: null,
      });
    });
  });
});
