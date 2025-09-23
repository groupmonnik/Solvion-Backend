import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from '../auth.service';
import { JwtService } from '@nestjs/jwt';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '@/users/entities/user.entity';
import { HttpExceptionCustom } from '@/common/exceptions/custom/custom.exception';
import { HttpStatus } from '@nestjs/common';

describe('AuthService', () => {
  let service: AuthService;
  let mockUserRepo: jest.Mocked<Repository<User>>;
  let mockJwt: jest.Mocked<JwtService>;

  beforeEach(async () => {
    mockUserRepo = {
      findOne: jest.fn(),
    } as any;

    mockJwt = {
      sign: jest.fn(),
      verify: jest.fn(),
    } as any;

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: getRepositoryToken(User), useValue: mockUserRepo },
        { provide: JwtService, useValue: mockJwt },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  // ---------- generate ----------
  describe('generate', () => {
    it('deve gerar accessToken e refreshToken quando credenciais forem válidas', async () => {
      const mockUser = { id: 1, email: 'test@test.com', password: '123' } as User;
      mockUserRepo.findOne.mockResolvedValue(mockUser);
      mockJwt.sign.mockReturnValueOnce('access-token').mockReturnValueOnce('refresh-token');

      const result = await service.generate({ email: 'test@test.com', password: '123' });

      expect(result).toEqual({ accessToken: 'access-token', refreshToken: 'refresh-token' });
      expect(mockJwt.sign).toHaveBeenCalledTimes(2);
    });

    it('deve lançar NOT_FOUND se usuário não existir', async () => {
      mockUserRepo.findOne.mockResolvedValue(null);

      await expect(service.generate({ email: 'nao@existe.com', password: '123' })).rejects.toThrow(
        new HttpExceptionCustom(null, HttpStatus.NOT_FOUND, 'user not found'),
      );
    });

    it('deve lançar BAD_REQUEST se senha for incorreta', async () => {
      const mockUser = { id: 1, email: 'test@test.com', password: '123' } as User;
      mockUserRepo.findOne.mockResolvedValue(mockUser);

      await expect(service.generate({ email: 'test@test.com', password: 'wrong' })).rejects.toThrow(
        new HttpExceptionCustom(null, HttpStatus.BAD_REQUEST, 'password is incorrect'),
      );
    });
  });

  // ---------- refreshToken ----------
  describe('refreshToken', () => {
    it('deve chamar verify e retornar novos tokens', async () => {
      const mockUser = { id: 1, email: 'test@test.com', password: '123' } as User;

      jest.spyOn(service, 'verify').mockResolvedValue(mockUser);
      jest.spyOn(service, 'generate').mockResolvedValue({
        accessToken: 'new-access',
        refreshToken: 'new-refresh',
      });

      const result = await service.refreshToken('refresh-token');
      expect(service.verify).toHaveBeenCalledWith('refresh-token');
      expect(service.generate).toHaveBeenCalledWith({ email: 'test@test.com', password: '123' });
      expect(result).toEqual({ accessToken: 'new-access', refreshToken: 'new-refresh' });
    });

    it('deve lançar UNAUTHORIZED se verify lançar erro inesperado', async () => {
      jest.spyOn(service, 'verify').mockImplementation(() => {
        throw new Error('invalid token');
      });

      await expect(service.refreshToken('bad-token')).rejects.toThrow(HttpExceptionCustom);
      await expect(service.refreshToken('bad-token')).rejects.toThrow('Invalid refresh token');
    });

    it('deve relançar erro se for HttpExceptionCustom', async () => {
      const customError = new HttpExceptionCustom(null, HttpStatus.NOT_FOUND, 'User not found');
      jest.spyOn(service, 'verify').mockImplementation(() => {
        throw customError;
      });

      await expect(service.refreshToken('token')).rejects.toBe(customError);
    });
  });

  // ---------- verify ----------
  describe('verify', () => {
    it('deve retornar usuário válido quando token for válido', async () => {
      const mockUser = { id: 1, email: 'test@test.com', password: '123' } as User;

      mockJwt.verify.mockReturnValue({ sub: 1 });
      mockUserRepo.findOne.mockResolvedValue(mockUser);

      const result = await service.verify('valid-token');
      expect(result).toEqual(mockUser);
    });

    it('deve lançar NOT_FOUND se usuário não existir', async () => {
      mockJwt.verify.mockReturnValue({ sub: 1 });
      mockUserRepo.findOne.mockResolvedValue(null);

      await expect(service.verify('token')).rejects.toThrow(
        new HttpExceptionCustom(null, HttpStatus.NOT_FOUND, 'User not found'),
      );
    });

    it('deve lançar INTERNAL_SERVER_ERROR se ocorrer erro inesperado (Error)', async () => {
      mockJwt.verify.mockImplementation(() => {
        throw new Error('Erro inesperado');
      });

      await expect(service.verify('token')).rejects.toThrow(HttpExceptionCustom);
      await expect(service.verify('token')).rejects.toThrow('Internal Server Error');
    });

    it('deve lançar INTERNAL_SERVER_ERROR mesmo se o erro for cru (string)', async () => {
      mockJwt.verify.mockImplementation(() => {
        throw 'erro cru' as unknown;
      });

      try {
        await service.verify('token');
      } catch (err: unknown) {
        expect(err).toBeInstanceOf(HttpExceptionCustom);
        expect((err as HttpExceptionCustom).getStatus()).toBe(HttpStatus.INTERNAL_SERVER_ERROR);
        expect((err as HttpExceptionCustom).message).toBe('Internal Server Error');
      }
    });

    it('deve relançar o erro se já for uma instância de HttpExceptionCustom', async () => {
      const customError = new HttpExceptionCustom(null, HttpStatus.BAD_REQUEST, 'custom');
      mockJwt.verify.mockImplementation(() => {
        throw customError;
      });

      await expect(service.verify('token')).rejects.toBe(customError);
    });

    // ✅ Novo teste que cobre o branch "catch (error instanceof HttpExceptionCustom)"
    it('deve capturar e relançar HttpExceptionCustom no catch', async () => {
      const customError = new HttpExceptionCustom(null, HttpStatus.UNAUTHORIZED, 'jwt expired');
      mockJwt.verify.mockImplementation(() => {
        throw customError;
      });

      await expect(service.verify('expired-token')).rejects.toBe(customError);
    });
    it('deve lançar UNAUTHORIZED se verify retornar null', async () => {
      jest.spyOn(service, 'verify').mockResolvedValue(null as unknown as User);

      await expect(service.refreshToken('null-token')).rejects.toThrow(
        new HttpExceptionCustom(null, HttpStatus.UNAUTHORIZED, 'invalid refresh token'),
      );
    });
  });
});
