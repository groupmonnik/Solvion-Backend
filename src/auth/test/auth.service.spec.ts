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
import { HttpExceptionCustom } from '@/common/exceptions/custom/custom.exception';
import { HttpStatus } from '@nestjs/common';
import accessTokenJwtConfig from '@/auth/config/access-token-jwt.config';
import refreshTokenJwtConfig from '@/auth/config/refresh-token-jwt.config';
import { ConfigType } from '@nestjs/config';
import { setupTestJwtConfig, clearTestJwtConfig } from '@/common/test/test-jwt-config.util';

describe('AuthService', () => {
  let service: AuthService;
  let userRepository: jest.Mocked<Repository<User>>;
  let jwtService: JwtService;
  let encryptService: EncryptService;
  let accessTokenConfig: ConfigType<typeof accessTokenJwtConfig>;
  let refreshTokenConfig: ConfigType<typeof refreshTokenJwtConfig>;

  let validateAccessToken: (params: { token: string; expectedEmail: string }) => void;
  let validateRefreshToken: (params: { token: string; expectedSub: number }) => void;

  let mockUser: User;
  const mockPassword: string = 'valid-password';

  // ✅ Setup test configuration using utility
  const testConfig = setupTestJwtConfig({
    cryptoKey: '0000000000000000000000000000000000000000000000000000000000000000',
  });

  beforeAll(async () => {
    const hashedPassword: string = await bcrypt.hash(mockPassword, 10);
    mockUser = {
      id: 1,
      email: 'test@example.com',
      password: hashedPassword,
    } as User;
  });

  afterAll(() => {
    clearTestJwtConfig();
  });

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
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

    service = module.get<AuthService>(AuthService);
    userRepository = module.get(getRepositoryToken(User));
    jwtService = module.get(JwtService);
    encryptService = module.get(EncryptService);
    accessTokenConfig = module.get(accessTokenJwtConfig.KEY);
    refreshTokenConfig = module.get(refreshTokenJwtConfig.KEY);

    validateAccessToken = ({ token, expectedEmail }) => {
      const decryptedToken: string = encryptService.decrypt(token);
      const payload: JwtPayload = jwtService.verify(decryptedToken, accessTokenConfig);
      expect(payload.email).toBe(expectedEmail);
      expect(payload.sub).toBeDefined();
    };

    validateRefreshToken = ({ token, expectedSub }) => {
      const decryptedToken: string = encryptService.decrypt(token);
      const payload: JwtPayload = jwtService.verify(decryptedToken, refreshTokenConfig);
      expect(payload.sub).toBe(expectedSub);
      expect(payload.email).toBeUndefined();
    };
  });

  describe('generateTokens', () => {
    it('should generate valid access and refresh tokens', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);

      const generateTokensResult = await service.generateTokens({
        email: mockUser.email,
        password: mockPassword,
      });

      expect(generateTokensResult).toHaveProperty('accessToken');
      expect(generateTokensResult).toHaveProperty('refreshToken');
      expect(typeof generateTokensResult.accessToken).toBe('string');
      expect(typeof generateTokensResult.refreshToken).toBe('string');

      validateAccessToken({
        token: generateTokensResult.accessToken,
        expectedEmail: mockUser.email,
      });
      validateRefreshToken({
        token: generateTokensResult.refreshToken,
        expectedSub: mockUser.id,
      });
    });

    it('should throw error if user is not found', async () => {
      userRepository.findOne.mockResolvedValue(null);

      const generateTokensPromise = service.generateTokens({
        email: 'no-user@example.com',
        password: mockPassword,
      });

      await expect(generateTokensPromise).rejects.toThrow('User not found');
    });

    it('should throw error if password is incorrect', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);

      const generateTokensPromise = service.generateTokens({
        email: mockUser.email,
        password: 'wrong-password',
        isRefresh: false,
      });

      await expect(generateTokensPromise).rejects.toThrow('Password is incorrect');
      await expect(generateTokensPromise).rejects.toThrow(HttpExceptionCustom);
    });

    it('should generate tokens without password validation when isRefresh is true', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);

      const generateTokensResult = await service.generateTokens({
        email: mockUser.email,
        password: mockUser.password,
        isRefresh: true,
      });

      expect(generateTokensResult).toHaveProperty('accessToken');
      expect(generateTokensResult).toHaveProperty('refreshToken');
      expect(typeof generateTokensResult.accessToken).toBe('string');
      expect(typeof generateTokensResult.refreshToken).toBe('string');
    });

    it('should use userRepository.findOne with correct parameters', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);

      await service.generateTokens({
        email: mockUser.email,
        password: mockPassword,
      });

      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { email: mockUser.email },
      });
    });

    it('should use jwtService.sign for access token with correct configuration', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);
      const signSpy = jest.spyOn(jwtService, 'sign');

      await service.generateTokens({
        email: mockUser.email,
        password: mockPassword,
      });

      expect(signSpy).toHaveBeenCalledWith(
        { sub: mockUser.id, email: mockUser.email },
        testConfig.accessToken,
      );
    });

    it('should use jwtService.sign for refresh token with correct configuration', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);
      const signSpy = jest.spyOn(jwtService, 'sign');

      await service.generateTokens({
        email: mockUser.email,
        password: mockPassword,
      });

      expect(signSpy).toHaveBeenCalledWith({ sub: mockUser.id }, testConfig.refreshToken);
    });

    it('should encrypt both access and refresh tokens', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);
      const encryptSpy = jest.spyOn(encryptService, 'encrypt');

      await service.generateTokens({
        email: mockUser.email,
        password: mockPassword,
      });

      expect(encryptSpy).toHaveBeenCalledTimes(2);
    });
  });

  describe('refreshToken', () => {
    it('should renew tokens with valid refresh token', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);

      const initialTokensResult = await service.generateTokens({
        email: mockUser.email,
        password: mockPassword,
      });

      const refreshTokenResult = await service.refreshToken(initialTokensResult.refreshToken);

      expect(refreshTokenResult).toHaveProperty('accessToken');
      expect(refreshTokenResult).toHaveProperty('refreshToken');
      expect(typeof refreshTokenResult.accessToken).toBe('string');
      expect(typeof refreshTokenResult.refreshToken).toBe('string');

      validateAccessToken({
        token: refreshTokenResult.accessToken,
        expectedEmail: mockUser.email,
      });
      validateRefreshToken({
        token: refreshTokenResult.refreshToken,
        expectedSub: mockUser.id,
      });
    });

    it('should throw error if user is not found after verifying token', async () => {
      const validRefreshToken: string = jwtService.sign({ sub: 999 }, testConfig.refreshToken);

      const encryptedRefreshToken: string = encryptService.encrypt(validRefreshToken);

      userRepository.findOne.mockResolvedValue(null);

      const refreshTokenPromise = service.refreshToken(encryptedRefreshToken);

      await expect(refreshTokenPromise).rejects.toThrow('Invalid refresh token');
    });

    it('should rethrow HttpExceptionCustom when error occurs in refreshToken', async () => {
      const customError: HttpExceptionCustom = new HttpExceptionCustom(
        null,
        HttpStatus.FORBIDDEN,
        'Custom refresh error',
      );

      jest.spyOn(encryptService, 'decrypt').mockImplementation(() => {
        throw customError;
      });

      const refreshTokenPromise = service.refreshToken('some-token');

      await expect(refreshTokenPromise).rejects.toThrow(customError);
    });

    it('should decrypt refresh token before verifying', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);
      const decryptSpy = jest.spyOn(encryptService, 'decrypt');

      const initialTokensResult = await service.generateTokens({
        email: mockUser.email,
        password: mockPassword,
      });

      await service.refreshToken(initialTokensResult.refreshToken);

      expect(decryptSpy).toHaveBeenCalledWith(initialTokensResult.refreshToken);
    });

    it('should call verifyToken with isRefresh true', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);
      const verifyTokenSpy = jest.spyOn(service, 'verifyToken');

      const initialTokensResult = await service.generateTokens({
        email: mockUser.email,
        password: mockPassword,
      });

      const decryptedToken: string = encryptService.decrypt(initialTokensResult.refreshToken);

      await service.refreshToken(initialTokensResult.refreshToken);

      expect(verifyTokenSpy).toHaveBeenCalledWith({
        token: decryptedToken,
        isRefresh: true,
      });
    });
  });

  describe('verifyToken', () => {
    it('should return valid user with access token', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);

      const accessToken: string = jwtService.sign(
        { sub: mockUser.id, email: mockUser.email },
        testConfig.accessToken,
      );

      const verifyTokenResult: User | null = await service.verifyToken({
        token: accessToken,
        isRefresh: false,
      });

      expect(verifyTokenResult).toEqual(mockUser);
      expect(verifyTokenResult).not.toBeNull();
    });

    it('should return valid user with refresh token', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);

      const refreshToken: string = jwtService.sign({ sub: mockUser.id }, testConfig.refreshToken);

      const verifyTokenResult: User | null = await service.verifyToken({
        token: refreshToken,
        isRefresh: true,
      });

      expect(verifyTokenResult).toEqual(mockUser);
      expect(verifyTokenResult).not.toBeNull();
    });

    it('should return null if token is valid but user does not exist', async () => {
      userRepository.findOne.mockResolvedValue(null);

      const accessToken: string = jwtService.sign(
        { sub: 999, email: 'nonexistent@example.com' },
        testConfig.accessToken,
      );

      const verifyTokenResult: User | null = await service.verifyToken({
        token: accessToken,
        isRefresh: false,
      });

      expect(verifyTokenResult).toBeNull();
    });

    it('should rethrow HttpExceptionCustom in verifyToken', async () => {
      const customError: HttpExceptionCustom = new HttpExceptionCustom(
        null,
        HttpStatus.FORBIDDEN,
        'Custom verify error',
      );

      jest.spyOn(jwtService, 'verify').mockImplementation(() => {
        throw customError;
      });

      const verifyTokenPromise = service.verifyToken({
        token: 'some-token',
        isRefresh: false,
      });

      await expect(verifyTokenPromise).rejects.toThrow(customError);
      await expect(verifyTokenPromise).rejects.toThrow('Custom verify error');
    });

    it('should use correct secret for access token verification', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);
      const verifySpy = jest.spyOn(jwtService, 'verify');

      const accessToken: string = jwtService.sign(
        { sub: mockUser.id, email: mockUser.email },
        testConfig.accessToken,
      );

      await service.verifyToken({
        token: accessToken,
        isRefresh: false,
      });

      expect(verifySpy).toHaveBeenCalledWith(accessToken, {
        secret: testConfig.accessToken.secret,
      });
    });

    it('should use correct secret for refresh token verification', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);
      const verifySpy = jest.spyOn(jwtService, 'verify');

      const refreshToken: string = jwtService.sign(
        { sub: mockUser.id },
        { secret: service['refreshTokenConfiguration'].secret, expiresIn: '7d' },
      );

      await service.verifyToken({
        token: refreshToken,
        isRefresh: true,
      });

      expect(verifySpy).toHaveBeenCalledWith(refreshToken, {
        secret: service['refreshTokenConfiguration'].secret,
      });
    });

    it('should handle token without sub property', async () => {
      userRepository.findOne.mockResolvedValue(null);

      jest.spyOn(jwtService, 'verify').mockReturnValue({
        email: 'test@example.com',
      } as JwtPayload);

      const verifyTokenResult: User | null = await service.verifyToken({
        token: 'token-without-sub',
        isRefresh: false,
      });

      expect(verifyTokenResult).toBeNull();
      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { id: -1 },
      });
    });
  });
});
