import { Test, TestingModule } from '@nestjs/testing';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import { ValidationPipe, HttpStatus } from '@nestjs/common';
import request from 'supertest';
import { TypeOrmModule } from '@nestjs/typeorm';
import { GoogleAccountsController } from '@/google-accounts/google-accounts.controller';
import { GoogleAccountsService } from '@/google-accounts/google-accounts.service';
import { ConfigService } from '@nestjs/config';
import { decode } from 'jsonwebtoken';
import axios from 'axios';
import { User } from '@/users/entities/user.entity';

jest.mock('axios');
jest.mock('jsonwebtoken');

describe('GoogleAccountsController (Integration with mocked code)', () => {
  let app: NestFastifyApplication;
  let service: GoogleAccountsService;
  let mockedAxios: jest.Mocked<typeof axios>;
  let mockedDecode: jest.MockedFunction<typeof decode>;

  const mockConfigService = {
    get: (key: string) => {
      const values: Record<string, string> = {
        GOOGLE_CLIENT_ID: 'test-client-id',
        GOOGLE_CLIENT_SECRET: 'test-client-secret',
        GOOGLE_REDIRECT_URI: 'http://localhost/google/redirect',
        GOOGLE_TOKEN_URI: 'https://oauth2.googleapis.com/token',
      };
      return values[key];
    },
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
    mockedAxios = axios as jest.Mocked<typeof axios>;
    mockedDecode = decode as jest.MockedFunction<typeof decode>;
  });

  afterAll(async () => {
    await app.close();
  });
  // * se você de um coverage ele vai dizer q da 9 a 20  foi testado mas ele foi sim, o problema é entre o nest e o jest :)
  describe('GET /google/accounts/login', () => {
    it('should call handleLogin and redirect', async () => {
      const response = await request(app.getHttpServer())
        .get('/google/accounts/login')
        .expect(HttpStatus.FOUND);

      expect(response.headers['location']).toBe(service.getAuthUrl());
    });
  });

  describe('GET /google/accounts/redirect', () => {
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
      azp: 'test-client-id',
      sub: '123456789',
      email: 'test@example.com',
      email_verified: true,
      name: 'Test User',
      picture: 'http://example.com/pic.jpg',
      given_name: 'Test',
      family_name: 'User',
      locale: 'en',
      iat: 1234567890,
      exp: 1234569999,
    };

    it('should handle redirect and return Ok message', async () => {
      mockedAxios.post.mockResolvedValue({ data: fakeTokens });
      mockedDecode.mockReturnValue(fakeDecodedToken);

      const code = 'mocked-code';
      const response = await request(app.getHttpServer())
        .get('/google/accounts/redirect')
        .query({ code })
        .expect(HttpStatus.OK);
      const postSpyOn = jest.spyOn(mockedAxios, 'post');
      expect(response.body).toEqual({
        statusCode: HttpStatus.OK,
        message: '',
        success: true,
        data: null,
      });
      expect(postSpyOn).toHaveBeenCalledWith(
        'https://oauth2.googleapis.com/token',
        expect.stringContaining(`code=${code}`),
        expect.objectContaining({
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        }),
      );
      expect(mockedDecode).toHaveBeenCalledWith('mock-id-token');
    });

    it('should return error if axios.post fails', async () => {
      mockedAxios.post.mockRejectedValue(new Error('Network Error'));
      const code = 'mocked-code';

      const response = await request(app.getHttpServer())
        .get('/google/accounts/redirect')
        .query({ code })
        .expect(HttpStatus.INTERNAL_SERVER_ERROR);

      // Check the actual error response structure
      expect(response.status).toBe(HttpStatus.INTERNAL_SERVER_ERROR);
      expect(response.body).toHaveProperty('message');
    });

    it('should return error if decode returns null', async () => {
      mockedAxios.post.mockResolvedValue({ data: fakeTokens });
      mockedDecode.mockReturnValue(null);

      const code = 'mocked-code';
      const response = await request(app.getHttpServer())
        .get('/google/accounts/redirect')
        .query({ code })
        .expect(HttpStatus.BAD_REQUEST);
      expect(response.status).toBe(HttpStatus.BAD_REQUEST);
      expect(response.body).toEqual({
        message: 'Invalid ID token: could not decode',
        data: null,
      });
    });
  });
});
