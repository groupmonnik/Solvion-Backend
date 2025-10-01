import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from '@/auth/auth.service';
import { Repository } from 'typeorm';
import { User } from '@/users/entities/user.entity';
import { JwtService } from '@nestjs/jwt';
import { EncryptService } from '@/common/encrypt/encrypt.service.auth';
import { getRepositoryToken } from '@nestjs/typeorm';
import { PasswordService } from '@/common/encrypt/password.service';
import * as bcrypt from 'bcrypt';
import { JwtPayload } from '@/auth/types/service/payloads/jwt-payload.type';

process.env.CRYPTO_KEY = '0000000000000000000000000000000000000000000000000000000000000000';

describe('AuthService', () => {
  let service: AuthService;
  let userRepository: jest.Mocked<Repository<User>>;
  let jwtService: JwtService;
  let encryptService: EncryptService;
  let validateAccessToken: (params: { token: string; expectedEmail: string }) => void;
  let validateRefreshToken: (params: { token: string; expectedSub: number }) => void;

  let mockUser: User;
  const mockPassword = 'valid-password';

  beforeAll(async () => {
    const hashedPassword = await bcrypt.hash(mockPassword, 10);
    mockUser = {
      id: 1,
      email: 'test@example.com',
      password: hashedPassword,
    } as User;
  });

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        PasswordService,
        {
          provide: getRepositoryToken(User),
          useValue: { findOne: jest.fn() },
        },
        JwtService,
        EncryptService,
        {
          provide: 'CONFIGURATION(accessTokenJwt)',
          useValue: { secret: 'test-access-secret' },
        },
        {
          provide: 'CONFIGURATION(refreshTokenJwt)',
          useValue: { secret: 'test-refresh-secret' },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    userRepository = module.get(getRepositoryToken(User));
    jwtService = module.get(JwtService);
    encryptService = module.get(EncryptService);

    validateAccessToken = ({ token, expectedEmail }) => {
      const decrypted = encryptService.decrypt(token);
      const payload: JwtPayload = jwtService.verify(decrypted, {
        secret: service['accessTokenConfiguration'].secret,
      });
      expect(payload.email).toBe(expectedEmail);
      expect(payload.sub).toBeDefined();
    };

    validateRefreshToken = ({ token, expectedSub }) => {
      const decrypted = encryptService.decrypt(token);
      const payload: JwtPayload = jwtService.verify(decrypted, {
        secret: service['refreshTokenConfiguration'].secret,
      });
      expect(payload.sub).toBe(expectedSub);
      expect(payload.email).toBeUndefined();
    };
  });

  describe('AuthService - configurações', () => {
    it('deve expor corretamente a configuração do access token', () => {
      expect(service['accessTokenConfiguration']).toEqual({
        secret: 'test-access-secret',
      });
    });
  });

  describe('generateTokens', () => {
    it('deve gerar access e refresh tokens válidos', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);

      const tokens = await service.generateTokens({
        email: mockUser.email,
        password: mockPassword,
      });

      validateAccessToken({ token: tokens.accessToken, expectedEmail: mockUser.email });
      validateRefreshToken({ token: tokens.refreshToken, expectedSub: mockUser.id });
    });

    it('deve lançar erro se usuário não for encontrado', async () => {
      userRepository.findOne.mockResolvedValue(null);

      const promise = service.generateTokens({
        email: 'no-user@example.com',
        password: mockPassword,
      });
      await expect(promise).rejects.toThrow('user not found');
    });
  });

  describe('refreshToken', () => {
    it('deve renovar tokens com refresh token válido', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);

      const tokens = await service.generateTokens({
        email: mockUser.email,
        password: mockPassword,
      });

      const result = await service.refreshToken(tokens.refreshToken);

      validateAccessToken({ token: result.accessToken, expectedEmail: mockUser.email });
      validateRefreshToken({ token: result.refreshToken, expectedSub: mockUser.id });
    });

    it('deve lançar erro se o token for inválido', async () => {
      const promise = service.refreshToken('token-invalido');
      await expect(promise).rejects.toThrow('Invalid refresh token');
    });
  });

  describe('verifyToken', () => {
    it('deve retornar o usuário válido com access token', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);

      const accessToken = jwtService.sign(
        { sub: mockUser.id, email: mockUser.email },
        { secret: service['accessTokenConfiguration'].secret, expiresIn: '15m' },
      );

      const user = await service.verifyToken({ token: accessToken, isRefresh: false });
      expect(user).toEqual(mockUser);
    });

    it('deve retornar o usuário válido com refresh token', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);

      const refreshToken = jwtService.sign(
        { sub: mockUser.id },
        { secret: service['refreshTokenConfiguration'].secret, expiresIn: '7d' },
      );

      const user = await service.verifyToken({ token: refreshToken, isRefresh: true });
      expect(user).toEqual(mockUser);
    });

    it('deve retornar null se o token for válido mas o usuário não existir', async () => {
      userRepository.findOne.mockResolvedValue(null);

      const accessToken = jwtService.sign(
        { sub: 999, email: 'nonexistent@example.com' },
        { secret: service['accessTokenConfiguration'].secret, expiresIn: '15m' },
      );

      const result = await service.verifyToken({ token: accessToken, isRefresh: false });
      expect(result).toBeNull();
    });

    it('deve lançar erro se o token for inválido', async () => {
      const promise = service.verifyToken({ token: 'token-invalido', isRefresh: false });
      await expect(promise).rejects.toThrow('Internal Server Error');
    });

    it('deve relançar HttpExceptionCustom no verifyToken', async () => {
      const promise = service.verifyToken({ token: 'any', isRefresh: false });
      await expect(promise).rejects.toThrow('Internal Server Error');
    });
  });
});
