import { Test, TestingModule } from '@nestjs/testing';
import { ValidationPipe, HttpStatus } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import request from 'supertest';
import { AuthModule } from '@/auth/auth.module';
import { User } from '@/users/entities/user.entity';
import { Repository } from 'typeorm';
import { getRepositoryToken } from '@nestjs/typeorm';
import { AuthService } from '@/auth/auth.service';
import { LoginDto } from '@/auth/dto/login-auth.dto';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import cookieParser from '@fastify/cookie';
import { PasswordService } from '@/common/encrypt/password.service';
import { EncryptService } from '@/common/encrypt/encrypt.service.auth';
import * as cookieSignature from 'cookie-signature';

describe('AuthController (Integration)', () => {
  let app: NestFastifyApplication;
  let userRepository: Repository<User>;
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  let authService: AuthService;

  const COOKIE_SECRET = 'test-secret';
  const DEFAULT_PASSWORD = 'Str0ngP@ssword!';

  beforeAll(() => {
    process.env.ACCESS_TOKEN_JWT_KEY = 'test-access-key';
    process.env.ACCESS_TOKEN_JWT_EXPIRES_IN = '3600s';
    process.env.REFRESH_TOKEN_JWT_KEY = 'test-refresh-key';
    process.env.REFRESH_TOKEN_JWT_EXPIRES_IN = '7d';
    process.env.CRYPTO_KEY = '10356586236241190c99852c49c3970e6e7b1f2f0f4a88cfe99bbfd3e61e4bd1';
  });

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
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
    })
      .overrideProvider(EncryptService)
      .useValue({
        encrypt: (text: string) => text,
        decrypt: (text: string) => text,
        compare: (plain: string, hashed: string) => plain === hashed,
      })
      .compile();

    app = moduleFixture.createNestApplication<NestFastifyApplication>(new FastifyAdapter());
    app.register(cookieParser as any, { secret: COOKIE_SECRET });
    app.useGlobalPipes(new ValidationPipe({ whitelist: true }));

    await app.init();
    await app.getHttpAdapter().getInstance().ready();

    userRepository = moduleFixture.get<Repository<User>>(getRepositoryToken(User));
    authService = moduleFixture.get<AuthService>(AuthService);
  });

  afterAll(async () => {
    await app.close();
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
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    return 's:' + cookieSignature.sign('invalidtoken', COOKIE_SECRET);
  };

  it('should login a user and set cookies', async () => {
    const user = await createTestUser('john@example.com');

    const loginDto: LoginDto = { email: user.email, password: DEFAULT_PASSWORD };
    const response = await request(app.getHttpServer())
      .post('/auth/login')
      .send(loginDto)
      .expect(HttpStatus.OK);

    expect(response.body).toEqual({ message: 'login successfully' });
    expect(response.headers['set-cookie']).toBeDefined();
  });

  it('should fail login with incorrect password', async () => {
    await createTestUser('john2@example.com');

    const loginDto: LoginDto = { email: 'john2@example.com', password: 'WrongP@ss1!' };
    const response = await request(app.getHttpServer())
      .post('/auth/login')
      .send(loginDto)
      .expect(HttpStatus.BAD_REQUEST);

    expect((response.body as { message: string }).message).toEqual('Password is incorrect');
  });

  it('should fail login with non-existent user', async () => {
    const loginDto: LoginDto = { email: 'notfound@example.com', password: 'AnyPass123!' };
    const response = await request(app.getHttpServer())
      .post('/auth/login')
      .send(loginDto)
      .expect(HttpStatus.NOT_FOUND);

    expect((response.body as { message: string }).message).toEqual('user not found');
  });

  it('should refresh token if valid refresh token is provided', async () => {
    const user = await createTestUser('jane@example.com');
    const refreshCookie = await loginAndGetRefreshCookie(user.email);
    expect(refreshCookie).toBeDefined();

    const response = await request(app.getHttpServer())
      .post('/auth/refresh')
      .set('Cookie', [refreshCookie as string])
      .expect(HttpStatus.OK);

    expect(response.body).toEqual({ message: 'new tokens generated' });
    expect(response.headers['set-cookie']).toBeDefined();
  });

  it('should fail refresh when no refresh token is provided', async () => {
    const response = await request(app.getHttpServer())
      .post('/auth/refresh')
      .expect(HttpStatus.UNAUTHORIZED);

    expect(response.body).toEqual({ message: 'No refresh token provided' });
  });

  it('should fail refresh with invalid refresh token', async () => {
    const invalidToken = getInvalidRefreshToken();

    const response = await request(app.getHttpServer())
      .post('/auth/refresh')
      .set('Cookie', [`refreshToken=${invalidToken}`])
      .expect(HttpStatus.UNAUTHORIZED);

    expect((response.body as { message: string }).message).toEqual(
      'Invalid refresh token signature',
    );
  });

  it('should logout and clear cookies', async () => {
    const response = await request(app.getHttpServer()).post('/auth/logout').expect(HttpStatus.OK);

    expect(response.body).toEqual({ message: 'Logged out successfully' });
    expect(response.headers['set-cookie']).toBeDefined();
  });
});
