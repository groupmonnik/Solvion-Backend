import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from '@/auth/auth.service';
import { Repository } from 'typeorm';
import { User } from '@/users/entities/user.entity';
import { JwtService } from '@nestjs/jwt';
import { EncryptService } from '@/common/encrypt/encrypt.service.auth';
import { getRepositoryToken } from '@nestjs/typeorm';
import { HttpExceptionCustom } from '@/common/exceptions/custom/custom.exception';
import { HttpStatus } from '@nestjs/common';
import { PasswordService } from '@/common/encrypt/password.service';

describe('AuthService', () => {
  let service: AuthService;
  let userRepository: jest.Mocked<Repository<User>>;
  let jwtService: jest.Mocked<JwtService>;
  let encryptService: jest.Mocked<EncryptService>;

  const mockUser: User = {
    id: 1,
    email: 'test@example.com',
    password: 'hashed-password',
  } as User;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: getRepositoryToken(User),
          useValue: {
            findOne: jest.fn(),
          },
        },
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn(),
            verify: jest.fn(),
          },
        },
        {
          provide: EncryptService,
          useValue: {
            encrypt: jest.fn(),
            decrypt: jest.fn(),
          },
        },
        {
          provide: 'CONFIGURATION(accessTokenJwt)',
          useValue: { secret: 'test-access-secret', expiresIn: '15m' },
        },
        {
          provide: 'CONFIGURATION(refreshTokenJwt)',
          useValue: { secret: 'test-refresh-secret', expiresIn: '7d' },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    userRepository = module.get(getRepositoryToken(User));
    jwtService = module.get(JwtService);
    encryptService = module.get(EncryptService);
  });
  describe('AuthService - configurações', () => {
    it('deve expor corretamente a configuração do access token', () => {
      expect(service['accessTokenConfiguration']).toEqual({
        secret: 'test-access-secret',
        expiresIn: '15m',
      });
    });
  });

  describe('generateTokens', () => {
    it('deve gerar access e refresh tokens válidos', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);
      jest.spyOn(PasswordService, 'verifyPassword').mockResolvedValue(true);
      jwtService.sign.mockReturnValueOnce('rawAccess').mockReturnValueOnce('rawRefresh');
      encryptService.encrypt.mockImplementation(t => `encrypted-${t}`);

      const result = await service.generateTokens({
        email: mockUser.email,
        password: 'valid-password',
      });

      expect(result).toEqual({
        accessToken: 'encrypted-rawAccess',
        refreshToken: 'encrypted-rawRefresh',
      });
      expect(jwtService.sign).toHaveBeenCalledTimes(2);
    });

    it('deve lançar erro se usuário não for encontrado', async () => {
      userRepository.findOne.mockResolvedValue(null);

      await expect(
        service.generateTokens({ email: 'no-user@example.com', password: '123' }),
      ).rejects.toThrow(new HttpExceptionCustom(null, HttpStatus.NOT_FOUND, 'user not found'));
    });

    it('deve lançar erro se senha não for passada no login normal', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);

      await expect(
        service.generateTokens({ email: mockUser.email, password: undefined }),
      ).rejects.toThrow(
        new HttpExceptionCustom(null, HttpStatus.BAD_REQUEST, 'Password is required'),
      );
    });

    it('deve lançar erro se a senha estiver incorreta', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);
      jest.spyOn(PasswordService, 'verifyPassword').mockResolvedValue(false);

      await expect(
        service.generateTokens({ email: mockUser.email, password: 'wrong' }),
      ).rejects.toThrow(
        new HttpExceptionCustom(null, HttpStatus.BAD_REQUEST, 'Password is incorrect'),
      );
    });

    it('não deve validar senha se for refresh token', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);
      jwtService.sign.mockReturnValueOnce('rawAccess').mockReturnValueOnce('rawRefresh');
      encryptService.encrypt.mockImplementation(t => `encrypted-${t}`);

      const result = await service.generateTokens({
        email: mockUser.email,
        password: undefined,
        isRefresh: true,
      });

      expect(result.accessToken).toContain('encrypted-rawAccess');
      expect(result.refreshToken).toContain('encrypted-rawRefresh');
    });
    it('deve gerar tokens válidos no login normal com senha correta', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);
      jest.spyOn(PasswordService, 'verifyPassword').mockResolvedValue(true);
      jwtService.sign.mockReturnValueOnce('rawAccess').mockReturnValueOnce('rawRefresh');
      encryptService.encrypt.mockImplementation(t => `encrypted-${t}`);

      const result = await service.generateTokens({
        email: mockUser.email,
        password: 'valid-password',
      });

      expect(result.accessToken).toBe('encrypted-rawAccess');
      expect(result.refreshToken).toBe('encrypted-rawRefresh');
    });
  });

  describe('refreshToken', () => {
    it('deve renovar tokens com refresh token válido', async () => {
      encryptService.decrypt.mockReturnValue('decrypted-refresh');
      jwtService.verify.mockReturnValue({ sub: 1, email: mockUser.email });
      userRepository.findOne.mockResolvedValue(mockUser);
      jest.spyOn(service, 'generateTokens').mockResolvedValue({
        accessToken: 'newAccess',
        refreshToken: 'newRefresh',
      });

      const result = await service.refreshToken('any-refresh');

      expect(result).toEqual({ accessToken: 'newAccess', refreshToken: 'newRefresh' });
    });
    it('deve retornar null quando decoded.sub for undefined (forçando -1)', async () => {
      jwtService.verify.mockReturnValue({ sub: undefined });
      userRepository.findOne.mockResolvedValue(null);

      const result = await service.verifyToken({ token: 'no-sub', isRefresh: false });

      expect(userRepository.findOne).toHaveBeenCalledWith({ where: { id: -1 } });
      expect(result).toBeNull();
    });

    it('deve lançar erro se o usuário não for encontrado no refresh', async () => {
      encryptService.decrypt.mockReturnValue('decrypted-refresh');
      jwtService.verify.mockReturnValue({ sub: 99 });
      userRepository.findOne.mockResolvedValue(null);

      await expect(service.refreshToken('invalid-refresh')).rejects.toThrow(
        new HttpExceptionCustom(null, HttpStatus.UNAUTHORIZED, 'invalid refresh token'),
      );
    });

    it('deve relançar HttpExceptionCustom se decrypt lançar esse erro', async () => {
      encryptService.decrypt.mockImplementation(() => {
        throw new HttpExceptionCustom(null, HttpStatus.UNAUTHORIZED, 'forced error');
      });

      await expect(service.refreshToken('invalid-refresh')).rejects.toThrow(HttpExceptionCustom);
    });

    it('deve lançar HttpExceptionCustom genérico se decrypt lançar erro normal', async () => {
      encryptService.decrypt.mockImplementation(() => {
        throw new Error('decrypt failed');
      });

      await expect(service.refreshToken('invalid-refresh')).rejects.toThrow(
        new HttpExceptionCustom(
          { error: expect.any(Error) },
          HttpStatus.UNAUTHORIZED,
          'Invalid refresh token',
        ),
      );
    });
  });

  describe('verifyToken', () => {
    it('deve retornar o usuário válido com access token', async () => {
      jwtService.verify.mockReturnValue({ sub: 1 });
      userRepository.findOne.mockResolvedValue(mockUser);

      const result = await service.verifyToken({ token: 'access', isRefresh: false });

      expect(result).toEqual(mockUser);
    });

    it('deve retornar o usuário válido com refresh token', async () => {
      jwtService.verify.mockReturnValue({ sub: 1 });
      userRepository.findOne.mockResolvedValue(mockUser);

      const result = await service.verifyToken({ token: 'refresh', isRefresh: true });

      expect(result).toEqual(mockUser);
    });

    it('deve relançar HttpExceptionCustom se verify lançar esse erro', async () => {
      jwtService.verify.mockImplementation(() => {
        throw new HttpExceptionCustom(null, HttpStatus.UNAUTHORIZED, 'forced error');
      });

      await expect(service.verifyToken({ token: 'invalid', isRefresh: false })).rejects.toThrow(
        HttpExceptionCustom,
      );
    });

    it('deve lançar HttpExceptionCustom genérico se verify lançar erro normal', async () => {
      jwtService.verify.mockImplementation(() => {
        throw new Error('verify failed');
      });

      await expect(service.verifyToken({ token: 'invalid', isRefresh: false })).rejects.toThrow(
        new HttpExceptionCustom(
          { error: expect.any(Error) },
          HttpStatus.INTERNAL_SERVER_ERROR,
          'Internal Server Error',
        ),
      );
    });
    it('deve retornar null se o token for válido mas o usuário não existir', async () => {
      jwtService.verify.mockReturnValue({ sub: 1 });
      userRepository.findOne.mockResolvedValue(null);

      const result = await service.verifyToken({ token: 'valid', isRefresh: false });

      expect(result).toBeNull();
    });
  });
});
