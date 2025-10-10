import { Test, TestingModule } from '@nestjs/testing';
import { ValidationPipe, HttpStatus } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import request from 'supertest';
import { AuthModule } from '@/auth/auth.module';
import { User } from '@/users/entities/user.entity';
import { Repository } from 'typeorm';
import { getRepositoryToken } from '@nestjs/typeorm';
import { LoginDto } from '@/auth/dto/login-auth.dto';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import cookieParser from '@fastify/cookie';
import { PasswordService } from '@/common/encrypt/password.service';
import { EncryptService } from '@/common/encrypt/encrypt.service.auth';
import * as cookieSignature from 'cookie-signature';
import { LoginResponse } from '@/auth/types/controller/responses/login-response.type';
import { HttpExceptionFilter } from '@/common/exception-filters/http-exception/http-exception.filter';
import { RefreshResponse } from '@/auth/types/controller/responses/refresh-response.type';
import { LogoutResponse } from '@/auth/types/controller/responses/logout-response.type';
import { JwtService } from '@nestjs/jwt';
import { AuthService } from '@/auth/auth.service';
import { setupTestJwtConfig, clearTestJwtConfig } from '@/common/test/test-jwt-config.util';

describe('AuthController (Integration)', () => {
  let app: NestFastifyApplication;
  let userRepository: Repository<User>;
  let jwtService: JwtService;
  let encryptService: EncryptService;
  let authService: AuthService;

  const DEFAULT_PASSWORD = 'Str0ngP@ssword!';

  // ✅ Setup test configuration using utility
  const testConfig = setupTestJwtConfig();

  beforeAll(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [
        AuthModule,
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
      providers: [
        PasswordService,
        JwtService,
        EncryptService,
        {
          provide: getRepositoryToken(User),
          useValue: { findOne: jest.fn() },
        },
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
    app.register(cookieParser as any, { secret: testConfig.cookie.secret });
    app.useGlobalPipes(new ValidationPipe({ whitelist: true }));
    app.useGlobalFilters(new HttpExceptionFilter());

    await app.init();
    await app.getHttpAdapter().getInstance().ready();

    userRepository = module.get<Repository<User>>(getRepositoryToken(User));

    authService = module.get(AuthService);
    jwtService = module.get(JwtService);
    encryptService = module.get(EncryptService);
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
      firstName: 'Test',
      lastName: 'User',
      email,
      password: hashed,
    });
    return await userRepository.save(user);
  };

  const loginAndGetRefreshCookie = async (
    email: string,
    password = DEFAULT_PASSWORD,
  ): Promise<string | undefined> => {
    const loginDto: LoginDto = { email, password };
    const loginResponse = await request(app.getHttpServer())
      .post('/auth/login')
      .send(loginDto)
      .expect(HttpStatus.OK);

    const setCookieHeader: string[] | undefined = loginResponse.headers['set-cookie'] as unknown as
      | string[]
      | undefined;
    if (!setCookieHeader) return undefined;

    const cookiesArray = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
    return cookiesArray.find(c => typeof c === 'string' && c.startsWith('refreshToken='));
  };

  const getInvalidRefreshToken = (): string => {
    return 's:' + cookieSignature.sign('invalidtoken', testConfig.cookie.secret);
  };

  describe('POST /auth/login', () => {
    it('should login a user and set cookies', async () => {
      const user = await createTestUser('john@example.com');

      const loginDto: LoginDto = { email: user.email, password: DEFAULT_PASSWORD };
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

      const loginDto: LoginDto = { email: 'john2@example.com', password: 'WrongP@ss1!' };
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
      const loginDto: LoginDto = { email: 'notfound@example.com', password: 'AnyPass123!' };
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

  describe('POST /auth/refresh', () => {
    it('should refresh token if valid refresh token is provided', async () => {
      const user = await createTestUser('john@example.com', DEFAULT_PASSWORD);
      const refreshCookie = await loginAndGetRefreshCookie(user.email, DEFAULT_PASSWORD);
      const verifySpy = jest.spyOn(authService, 'verifyToken');

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

      const verifyResult = verifySpy.mock.results[0];
      const verifyResultValue = await verifyResult.value;

      expect(verifyResultValue).toMatchObject({
        ...user,
      });
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

    it('should fail refresh when user does not exist', async () => {
      const verifySpy = jest.spyOn(jwtService, 'verify');
      const refreshPayload = { sub: 1, email: 'example@example.com' };
      const rawRefreshToken = jwtService.sign(refreshPayload, testConfig.refreshToken);
      const encryptedRefreshToken = encryptService.encrypt(rawRefreshToken);
      const cookie = cookieSignature.sign(encryptedRefreshToken, testConfig.cookie.secret);
      const response = await request(app.getHttpServer())
        .post('/auth/refresh')
        .set('Cookie', [`refreshToken=${cookie}`])
        .expect(HttpStatus.UNAUTHORIZED);

      expect(response.body).toEqual({
        statusCode: HttpStatus.UNAUTHORIZED,
        message: 'Invalid refresh token',
        success: false,
        data: null,
      } as RefreshResponse);

      expect(verifySpy).toHaveBeenCalled();
    });
  });

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
