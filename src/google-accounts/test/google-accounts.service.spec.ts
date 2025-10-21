import { HttpExceptionCustom } from '@/common/exceptions/custom/custom.exception';
import { GoogleAccountsService } from '@/google-accounts/google-accounts.service';
import { ConfigService } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import { Auth } from 'googleapis';

type MockOAuth2Client = jest.Mocked<
  Pick<
    Auth.OAuth2Client,
    | 'generateAuthUrl'
    | 'getToken'
    | 'verifyIdToken'
    | 'setCredentials'
    | 'getAccessToken'
    | 'credentials'
  >
>;

const oauth2ClientMock: MockOAuth2Client = {
  generateAuthUrl: jest.fn(),
  getToken: jest.fn(),
  verifyIdToken: jest.fn(),
  setCredentials: jest.fn(),
  getAccessToken: jest.fn(),
  credentials: {} as Auth.Credentials,
};

jest.mock('googleapis', () => ({
  google: {
    auth: {
      OAuth2: jest.fn().mockImplementation(() => oauth2ClientMock),
    },
  },
}));

describe('GoogleAccountsService', () => {
  let service: GoogleAccountsService;

  const mockConfigService = {
    get: (key: string): string => {
      const values: Record<string, string> = {
        GOOGLE_CLIENT_ID: 'test-client-id',
        GOOGLE_CLIENT_SECRET: 'test-client-secret',
        GOOGLE_REDIRECT_URI: 'http://localhost/callback',
      };
      return values[key];
    },
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [GoogleAccountsService, { provide: ConfigService, useValue: mockConfigService }],
    }).compile();

    service = module.get<GoogleAccountsService>(GoogleAccountsService);
  });

  describe('getAuthUrl', () => {
    it('should generate the correct URL with the expected parameters', () => {
      oauth2ClientMock.generateAuthUrl.mockReturnValue('https://example.com/auth');

      const result = service.getAuthUrl();

      expect(result).toBe('https://example.com/auth');
      expect(oauth2ClientMock.generateAuthUrl).toHaveBeenCalledWith({
        access_type: 'offline',
        prompt: 'consent',
        scope: ['openid', 'email', 'profile', 'https://www.googleapis.com/auth/adwords'],
      });
    });

    it('must return a string', () => {
      oauth2ClientMock.generateAuthUrl.mockReturnValue('https://auth.url');
      const result = service.getAuthUrl();
      expect(typeof result).toBe('string');
    });
  });

  describe('getTokens', () => {
    it('should return valid tokens when Google responds correctly', async () => {
      const fakeTokens = {
        access_token: 'token123',
        refresh_token: 'refresh123',
      };
      (oauth2ClientMock.getToken as jest.Mock).mockResolvedValue({ tokens: fakeTokens });

      const result = await service.getTokens('valid-code');
      expect(result).toEqual(fakeTokens);
      expect(oauth2ClientMock.getToken).toHaveBeenCalledWith('valid-code');
    });

    it('deve lançar erro se o Google lançar uma exceção', async () => {
      (oauth2ClientMock.getToken as jest.Mock).mockRejectedValue(new Error('invalid_grant'));
      const getToken = service.getTokens('bad-code');
      await expect(getToken).rejects.toThrow('invalid_grant');
    });

    it('deve lançar erro se o código estiver vazio', async () => {
      (oauth2ClientMock.getToken as jest.Mock).mockRejectedValue(new Error('Empty code'));
      const getToken = service.getTokens('');
      await expect(getToken).rejects.toThrow('Empty code');
    });
  });

  describe('decodeToken', () => {
    const fakePayload: Auth.TokenPayload = {
      iss: 'accounts.google.com',
      aud: 'test-client-id',
      sub: '123',
      email: 'user@example.com',
      iat: 0,
      exp: 0,
    };

    it('must return the correctly decoded payload', async () => {
      const getPayload = jest.fn().mockReturnValue(fakePayload);
      (oauth2ClientMock.verifyIdToken as jest.Mock).mockResolvedValue({
        getPayload,
      } as unknown as Auth.LoginTicket);

      const result = await service.decodeToken('valid-token');
      expect(result).toEqual(fakePayload);
      expect(oauth2ClientMock.verifyIdToken).toHaveBeenCalledWith({
        idToken: 'valid-token',
        audience: 'test-client-id',
      });
    });

    it('should throw error if verifyIdToken rejects', async () => {
      (oauth2ClientMock.verifyIdToken as jest.Mock).mockRejectedValue(new Error('invalid token'));
      const decodeToken = service.decodeToken('invalid-token');
      await expect(decodeToken).rejects.toThrow('invalid token');
    });

    it('should throw HttpExceptionCustom if payload is null', async () => {
      const getPayload = jest.fn().mockReturnValue(null);
      (oauth2ClientMock.verifyIdToken as jest.Mock).mockResolvedValue({
        getPayload,
      } as unknown as Auth.LoginTicket);
      const decodeToken = service.decodeToken('token');
      await expect(decodeToken).rejects.toThrow(HttpExceptionCustom);
      await expect(decodeToken).rejects.toThrow('Invalid ID token: could not decode');

      expect(oauth2ClientMock.verifyIdToken).toHaveBeenCalledWith({
        idToken: 'token',
        audience: 'test-client-id',
      });
    });
  });
});
