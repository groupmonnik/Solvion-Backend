import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from '@/auth/auth.controller';
import { AuthService } from '@/auth/auth.service';
import { LoginDto } from '@/auth/dto/login-auth.dto';
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
    it('deve retornar mensagem e setar cookies de accessToken e refreshToken', async () => {
      const dto: LoginDto = { email: 'test@test.com', password: '123' };
      authService.generate.mockResolvedValue({
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
      });

      const response: Response = await request(app.getHttpServer())
        .post('/auth/login')
        .send(dto)
        .expect(HttpStatus.OK);

      // body só mensagem
      expect(response.body).toEqual({
        message: 'login successfully',
      });

      // cookies devem existir
      expect(response.headers['set-cookie']).toBeDefined();
      expect(response.headers['set-cookie'][0]).toContain('accessToken=');
      expect(response.headers['set-cookie'][1]).toContain('refreshToken=');
    });
  });

  describe('/auth/refresh (POST)', () => {
    it('deve retornar novo accessToken e refreshToken e atualizar cookies', async () => {
      authService.refreshToken.mockResolvedValue({
        accessToken: 'new-access',
        refreshToken: 'new-refresh',
      });

      const response: Response = await request(app.getHttpServer())
        .post('/auth/refresh')
        .set('Cookie', 'refreshToken=old-refresh')
        .expect(HttpStatus.OK);

      expect(response.body).toEqual({ message: 'new tokens generated' });
      expect(response.headers['set-cookie']).toBeDefined();
      expect(authService.refreshToken).toHaveBeenCalledWith('old-refresh');
    });

    it('deve retornar 401 se não tiver refreshToken no cookie', async () => {
      const response: Response = await request(app.getHttpServer())
        .post('/auth/refresh')
        .expect(HttpStatus.UNAUTHORIZED);

      expect(response.body).toMatchObject({
        message: 'No refresh token provided',
      });
    });

    it('deve retornar 401 se o refreshToken vier vazio', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/refresh')
        .set('Cookie', 'refreshToken=')
        .expect(HttpStatus.UNAUTHORIZED);

      expect(response.body).toMatchObject({
        message: 'No refresh token provided',
      });
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
  });

  describe('/auth/logout (POST)', () => {
    it('deve limpar os cookies de accessToken e refreshToken e retornar mensagem', async () => {
      const response: Response = await request(app.getHttpServer())
        .post('/auth/logout')
        .expect(HttpStatus.OK);

      expect(response.body).toEqual({ message: 'Logged out successfully' });
      expect(response.headers['set-cookie']).toBeDefined();

      const rawCookies = response.headers['set-cookie'];
      const cookies = Array.isArray(rawCookies) ? rawCookies.join(';') : rawCookies;

      expect(cookies).toContain('accessToken=');
      expect(cookies).toContain('refreshToken=');
    });
  });
});
