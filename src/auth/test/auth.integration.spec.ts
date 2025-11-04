import { Test, TestingModule } from '@nestjs/testing';
import { ValidationPipe, HttpStatus } from '@nestjs/common';
import request from 'supertest';
import { AuthModule } from '@/auth/auth.module';
import { User } from '@/users/entities/user.entity';
import { Repository } from 'typeorm';
import { getRepositoryToken } from '@nestjs/typeorm';
import { LoginDto } from '@/auth/dto/login-auth.dto';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import cookieParser from '@fastify/cookie';
import { PasswordService } from '@/common/encrypt/password.service';
// REMOVIDO: import * as cookieSignature from "cookie-signature";
import { LoginResponse } from '@/auth/types/controller/responses/login-response.type';
import { HttpExceptionFilter } from '@/common/exception-filters/http-exception/http-exception.filter';
import { RefreshResponse } from '@/auth/types/controller/responses/refresh-response.type';
import { LogoutResponse } from '@/auth/types/controller/responses/logout-response.type';
import { setupTestJwtConfig, clearTestJwtConfig } from '@/common/test/test-jwt-config.util';
import { TestDatabaseModule } from '@/common/test/test-database.module';
import { UsersModule } from '@/users/users.module';

describe('AuthController (Integration)', () => {
  let app: NestFastifyApplication;
  let userRepository: Repository<User>;

  const DEFAULT_PASSWORD = 'Str0ngP@ssword!';

  const testConfig = setupTestJwtConfig();

  beforeAll(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [TestDatabaseModule, AuthModule, UsersModule],
      providers: [
        {
          provide: 'CONFIGURATION(accessTokenJwt)',
          useValue: testConfig.accessToken,
        },
        {
          provide: 'CONFIGURATION(refreshTokenJwt)',
          useValue: testConfig.refreshToken,
        },
      ],
    }).compile();

    app = module.createNestApplication<NestFastifyApplication>(new FastifyAdapter());

    // 🔑 CORREÇÃO (MANTIDA): Adicionado 'await'
    await app.register(cookieParser as any, {
      secret: testConfig.cookie.secret,
    });

    app.useGlobalPipes(new ValidationPipe({ whitelist: true }));
    app.useGlobalFilters(new HttpExceptionFilter());

    await app.init();
    await app.getHttpAdapter().getInstance().ready();

    userRepository = module.get<Repository<User>>(getRepositoryToken(User));
  });

  afterAll(async () => {
    await app.close();
    clearTestJwtConfig();
  });

  beforeEach(async () => {
    await userRepository.clear();
  });

  const createTestUser = async (email: string, password = DEFAULT_PASSWORD): Promise<User> => {
    const hashed = await PasswordService.hashPassword(password);
    const user = userRepository.create({
      name: 'Test User',
      email,
      password: hashed,
    });
    return await userRepository.save(user);
  };

  /**
   * Função revisada. Para falhar na assinatura,
   * basta enviar um token assinado com uma chave incorreta,
   * ou um valor que não siga o formato 's:<assinatura>.<valor>'.
   * O caso de 's:corrupted.invalid' já simula essa falha
   * de forma mais limpa, vamos reusá-lo aqui.
   */
  const getInvalidRefreshToken = (): string => {
    // Retornar um valor que o req.unsignCookie() irá falhar ao verificar
    // O valor 's:corrupted.invalid' já simula um cookie assinado com valor inválido.
    return 's:corrupted-signature-that-does-not-match.invalid-payload';
  };

  // ---

  describe('POST /auth/login', () => {
    it('should login a user and set cookies', async () => {
      const user = await createTestUser('john@example.com');

      const loginDto: LoginDto = {
        email: user.email,
        password: DEFAULT_PASSWORD,
      };
      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send(loginDto)
        .expect(HttpStatus.OK);

      expect(response.body).toEqual({
        statusCode: HttpStatus.OK,
        message: 'login successfully',
        success: true,
        data: null,
      } as LoginResponse);

      expect(response.headers['set-cookie']).toBeDefined();
    });

    it('should fail login with incorrect password', async () => {
      await createTestUser('john2@example.com');

      const loginDto: LoginDto = {
        email: 'john2@example.com',
        password: 'WrongP@ss1!',
      };
      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send(loginDto)
        .expect(HttpStatus.UNAUTHORIZED);

      expect(response.body).toEqual({
        statusCode: HttpStatus.UNAUTHORIZED,
        message: 'Password is incorrect',
        success: false,
        data: null,
      });
    });

    it('should fail login with non-existent user', async () => {
      const loginDto: LoginDto = {
        email: 'notfound@example.com',
        password: 'AnyPass123!',
      };
      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send(loginDto)
        .expect(HttpStatus.NOT_FOUND);

      expect(response.body).toEqual({
        statusCode: HttpStatus.NOT_FOUND,
        message: 'User not found',
        success: false,
        data: null,
      } as LoginResponse);
    });
  });

  // ---

  describe('POST /auth/refresh', () => {
    it('should refresh token if valid refresh token is provided', async () => {
      const user = await createTestUser('john@example.com', DEFAULT_PASSWORD);

      const loginResponse = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: user.email, password: DEFAULT_PASSWORD })
        .expect(HttpStatus.OK);

      const refreshCookie = (loginResponse.headers['set-cookie'] as unknown as string[]).find(c =>
        c.startsWith('refreshToken='),
      );

      expect(refreshCookie).toBeDefined();

      const response = await request(app.getHttpServer())
        .post('/auth/refresh')
        .set('Cookie', [refreshCookie as string])
        .expect(HttpStatus.OK);

      expect(response.body).toEqual({
        statusCode: HttpStatus.OK,
        message: 'New tokens generated',
        success: true,
        data: null,
      } as RefreshResponse);

      expect(response.headers['set-cookie']).toBeDefined();
    });

    it('should fail refresh when no refresh token is provided', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/refresh')
        .expect(HttpStatus.UNAUTHORIZED);

      expect(response.body).toEqual({
        statusCode: HttpStatus.UNAUTHORIZED,
        message: 'No refresh token provided',
        success: false,
        data: null,
      } as RefreshResponse);
    });

    // Reusando o novo método para simular falha de assinatura
    it('should fail refresh with Invalid refresh token signature', async () => {
      const invalidToken = getInvalidRefreshToken();

      const response = await request(app.getHttpServer())
        .post('/auth/refresh')
        .set('Cookie', [`refreshToken=${invalidToken}`])
        .expect(HttpStatus.UNAUTHORIZED);

      expect(response.body).toEqual({
        statusCode: HttpStatus.UNAUTHORIZED,
        message: 'Invalid refresh token signature',
        success: false,
        data: null,
      } as RefreshResponse);
    });

    it('should fail refresh with corrupted unsigned cookie value', async () => {
      // Este teste é redundante com o anterior, mas mantido para cobrir o cenário de 's:corrupted.invalid'
      const corruptedToken = 's:corrupted.invalid';

      const response = await request(app.getHttpServer())
        .post('/auth/refresh')
        .set('Cookie', [`refreshToken=${corruptedToken}`])
        .expect(HttpStatus.UNAUTHORIZED);

      expect(response.body).toEqual({
        statusCode: HttpStatus.UNAUTHORIZED,
        message: 'Invalid refresh token signature',
        success: false,
        data: null,
      } as RefreshResponse);
    });

    it('should fail refresh when unsignCookie returns invalid', async () => {
      const malformedToken = 'malformed-token-without-signature';

      const response = await request(app.getHttpServer())
        .post('/auth/refresh')
        .set('Cookie', [`refreshToken=${malformedToken}`])
        .expect(HttpStatus.UNAUTHORIZED);

      expect(response.body).toEqual({
        statusCode: HttpStatus.UNAUTHORIZED,
        message: 'Invalid refresh token signature',
        success: false,
        data: null,
      } as RefreshResponse);
    });

    it('should fail refresh when user associated with token does not exist (token is orphaned)', async () => {
      const user = await createTestUser('temp@example.com', DEFAULT_PASSWORD);

      const loginResponse = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: user.email, password: DEFAULT_PASSWORD })
        .expect(HttpStatus.OK);

      const refreshCookie = (loginResponse.headers['set-cookie'] as unknown as string[]).find(c =>
        c.startsWith('refreshToken='),
      );

      await userRepository.delete({ id: user.id });

      const response = await request(app.getHttpServer())
        .post('/auth/refresh')
        .set('Cookie', [refreshCookie as string])
        .expect(HttpStatus.UNAUTHORIZED);

      expect(response.body).toEqual({
        statusCode: HttpStatus.UNAUTHORIZED,
        message: 'Invalid refresh token',
        success: false,
        data: null,
      } as RefreshResponse);
    });
  });

  // --

  describe('POST /auth/logout', () => {
    it('should logout and clear cookies', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/logout')
        .expect(HttpStatus.OK);

      expect(response.body).toEqual({
        statusCode: HttpStatus.OK,
        message: 'Logged out successfully',
        success: true,
        data: null,
      } as LogoutResponse);

      expect(response.headers['set-cookie']).toBeDefined();
    });
  });
});
