import { Test, TestingModule } from '@nestjs/testing';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { ConfigModule } from '@nestjs/config';
import { Repository } from 'typeorm';
import { getRepositoryToken } from '@nestjs/typeorm';

import { AuthService } from '@/auth/auth.service';
import { User } from '@/users/entities/user.entity';
import { EncryptService } from '@/common/encrypt/encrypt.service.auth';
import { PasswordService } from '@/common/encrypt/password.service';
import { HttpExceptionCustom } from '@/common/exceptions/custom/custom.exception';

import accessTokenJwtConfig from '@/auth/config/access-token-jwt.config';
import refreshTokenJwtConfig from '@/auth/config/refresh-token-jwt.config';

describe('AuthService (Integration)', () => {
  let moduleRef: TestingModule;
  let authService: AuthService;
  let userRepository: Repository<User>;
  let encryptService: EncryptService;
  let jwtService: JwtService;
  let accessTokenConfig: { secret: string; expiresIn?: string };
  let refreshTokenConfig: { secret: string; expiresIn?: string };

  const plainPassword = 'SuperSecret123!';
  let hashedPassword: string;
  let testUser: User;

  beforeAll(async () => {
    hashedPassword = await PasswordService.hashPassword(plainPassword);

    moduleRef = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          load: [accessTokenJwtConfig, refreshTokenJwtConfig],
        }),
        JwtModule.register({}),
        TypeOrmModule.forRoot({
          type: 'sqlite',
          database: ':memory:',
          dropSchema: true,
          entities: [User],
          synchronize: true,
        }),
        TypeOrmModule.forFeature([User]),
      ],
      providers: [AuthService, EncryptService],
    }).compile();

    authService = moduleRef.get(AuthService);
    encryptService = moduleRef.get(EncryptService);
    userRepository = moduleRef.get<Repository<User>>(getRepositoryToken(User));
    jwtService = moduleRef.get(JwtService);

    accessTokenConfig = moduleRef.get(accessTokenJwtConfig.KEY);
    refreshTokenConfig = moduleRef.get(refreshTokenJwtConfig.KEY);
  });

  beforeEach(async () => {
    await userRepository.clear();

    testUser = userRepository.create({
      firstName: 'John',
      lastName: 'Doe',
      email: 'test@example.com',
      password: hashedPassword,
    });

    await userRepository.save(testUser);
  });

  afterAll(async () => {
    await moduleRef.close();
  });
  describe('generateTokens', () => {
    it('deve gerar tokens válidos com senha correta', async () => {
      const res = await authService.generateTokens({
        email: testUser.email,
        password: plainPassword,
      });

      expect(res).toHaveProperty('accessToken');
      expect(res).toHaveProperty('refreshToken');
    });

    it('deve falhar se usuário não existir', async () => {
      await expect(
        authService.generateTokens({ email: 'noone@example.com', password: plainPassword }),
      ).rejects.toBeInstanceOf(HttpExceptionCustom);
    });

    it('deve falhar se senha não for passada (login normal)', async () => {
      await expect(
        authService.generateTokens({ email: testUser.email, password: undefined }),
      ).rejects.toBeInstanceOf(HttpExceptionCustom);
    });

    it('deve falhar se senha for incorreta', async () => {
      await expect(
        authService.generateTokens({ email: testUser.email, password: 'wrong-password' }),
      ).rejects.toBeInstanceOf(HttpExceptionCustom);
    });

    it('não deve validar senha se for refresh token', async () => {
      const res = await authService.generateTokens({
        email: testUser.email,
        isRefresh: true,
      });

      expect(res).toHaveProperty('accessToken');
      expect(res).toHaveProperty('refreshToken');
    });
  });
  describe('refreshToken', () => {
    it('deve renovar tokens com refresh válido', async () => {
      const tokens = await authService.generateTokens({
        email: testUser.email,
        password: plainPassword,
      });

      const result = await authService.refreshToken(tokens.refreshToken);
      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('refreshToken');
    });

    it('deve falhar se refresh pertencer a usuário inexistente', async () => {
      const fakeRaw = jwtService.sign({ sub: 9999 }, { secret: refreshTokenConfig.secret });
      const encrypted = encryptService.encrypt(fakeRaw);

      await expect(authService.refreshToken(encrypted)).rejects.toBeInstanceOf(HttpExceptionCustom);
    });

    it('deve falhar se decrypt lançar erro genérico', async () => {
      const spy = jest.spyOn(encryptService, 'decrypt').mockImplementation(() => {
        throw new Error('forced decrypt error');
      });

      await expect(authService.refreshToken('whatever')).rejects.toBeInstanceOf(
        HttpExceptionCustom,
      );

      spy.mockRestore();
    });
  });

  describe('verifyToken', () => {
    it('deve retornar o usuário válido com access token', async () => {
      const raw = jwtService.sign({ sub: testUser.id }, { secret: accessTokenConfig.secret });
      const result = await authService.verifyToken({ token: raw, isRefresh: false });
      expect(result).not.toBeNull();
      expect(result?.email).toBe(testUser.email);
    });

    it('deve retornar o usuário válido com refresh token', async () => {
      const raw = jwtService.sign({ sub: testUser.id }, { secret: refreshTokenConfig.secret });
      const result = await authService.verifyToken({ token: raw, isRefresh: true });
      expect(result).not.toBeNull();
      expect(result?.id).toBe(testUser.id);
    });

    it('deve retornar null se sub for undefined (decoded.sub ?? -1)', async () => {
      const raw = jwtService.sign({}, { secret: accessTokenConfig.secret });
      const result = await authService.verifyToken({ token: raw, isRefresh: false });
      expect(result).toBeNull();
    });

    it('deve retornar null se usuário não existir', async () => {
      const raw = jwtService.sign({ sub: 9999 }, { secret: accessTokenConfig.secret });
      const result = await authService.verifyToken({ token: raw, isRefresh: false });
      expect(result).toBeNull();
    });

    it('deve lançar erro genérico se token for inválido', async () => {
      await expect(
        authService.verifyToken({ token: 'this-is-not-a-token', isRefresh: false }),
      ).rejects.toBeInstanceOf(HttpExceptionCustom);
    });
  });
});
