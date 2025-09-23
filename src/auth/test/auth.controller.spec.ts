import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from '../auth.controller';
import { AuthService } from '../auth.service';
import { LoginDto } from '../dto/login-auth.dto';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import { HttpStatus, UnauthorizedException } from '@nestjs/common';
import request, { Response } from 'supertest';
import fastifyCookie from '@fastify/cookie';

describe('AuthController (e2e)', () => {
  let app: NestFastifyApplication;
  let authService: jest.Mocked<AuthService>;

  beforeAll(async () => {
    const mockAuthService: jest.Mocked<AuthService> = {
      generate: jest.fn(),
      refreshToken: jest.fn(),
      verify: jest.fn(),
    } as unknown as jest.Mocked<AuthService>;

    const moduleFixture: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: mockAuthService,
        },
      ],
    }).compile();

    const fastifyAdapter = new FastifyAdapter();
    fastifyAdapter.register(fastifyCookie as any, {
      secret: 'test-secret',
    });

    app = moduleFixture.createNestApplication<NestFastifyApplication>(fastifyAdapter);
    await app.init();
    await app.getHttpAdapter().getInstance().ready();

    authService = app.get(AuthService);
  });

  afterAll(async () => {
    await app.close();
  });

  describe('/auth/login (POST)', () => {
    it('deve retornar accessToken e setar refreshToken no cookie', async () => {
      const dto: LoginDto = { email: 'test@test.com', password: '123' };
      authService.generate.mockResolvedValue({
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
      });

      const response: Response = await request(app.getHttpServer())
        .post('/auth/login')
        .send(dto)
        .expect(HttpStatus.OK);

      expect(response.body).toEqual({ accessToken: 'access-token' });
      expect(response.headers['set-cookie']).toBeDefined();
    });
  });

  describe('/auth/refresh (POST)', () => {
    it('deve retornar novo accessToken e atualizar refreshToken', async () => {
      authService.refreshToken.mockResolvedValue({
        accessToken: 'new-access',
        refreshToken: 'new-refresh',
      });

      const response: Response = await request(app.getHttpServer())
        .post('/auth/refresh')
        .set('Cookie', 'refreshToken=old-refresh')
        .expect(HttpStatus.OK);

      expect(response.body).toEqual({ accessToken: 'new-access' });
      expect(response.headers['set-cookie']).toBeDefined();
      expect(authService.refreshToken).toHaveBeenCalledWith('old-refresh');
    });

    it('deve retornar 401 se não tiver refreshToken no cookie', async () => {
      const response: Response = await request(app.getHttpServer())
        .post('/auth/refresh')
        .expect(HttpStatus.UNAUTHORIZED);

      expect(response.body).toEqual({ message: 'No refresh token provided' });
    });

    it('deve retornar 401 se o refreshToken vier vazio', async () => {
      const response: Response = await request(app.getHttpServer())
        .post('/auth/refresh')
        .set('Cookie', 'refreshToken=') // cookie vazio
        .expect(HttpStatus.UNAUTHORIZED);

      expect(response.body).toEqual({ message: 'No refresh token provided' });
    });

    it('deve retornar 401 se o refreshToken for inválido (AuthService lançar erro)', async () => {
      authService.refreshToken.mockRejectedValueOnce(
        new UnauthorizedException('Invalid refresh token'),
      );

      const response: Response = await request(app.getHttpServer())
        .post('/auth/refresh')
        .set('Cookie', 'refreshToken=invalid-token')
        .expect(HttpStatus.UNAUTHORIZED);

      expect(response.body).toHaveProperty('message', 'Invalid refresh token');
    });

    it('deve retornar 401 se o refreshToken vier vazio', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/refresh')
        .set('Cookie', 'refreshToken=') // cookie presente mas vazio
        .expect(HttpStatus.UNAUTHORIZED);

      expect(response.body).toEqual({ message: 'No refresh token provided' });
    });
  });

  describe('/auth/logout (POST)', () => {
    it('deve limpar o cookie e retornar mensagem de sucesso', async () => {
      const response: Response = await request(app.getHttpServer())
        .post('/auth/logout')
        .expect(HttpStatus.OK);

      expect(response.body).toEqual({ message: 'Logged out successfully' });
      expect(response.headers['set-cookie']).toBeDefined();
    });
  });
});
