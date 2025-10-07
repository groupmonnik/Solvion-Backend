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
    it('deve gerar a URL correta com os parâmetros esperados', () => {
      oauth2ClientMock.generateAuthUrl.mockReturnValue('https://example.com/auth');

      const result = service.getAuthUrl();

      expect(result).toBe('https://example.com/auth');
      expect(oauth2ClientMock.generateAuthUrl).toHaveBeenCalledWith({
        access_type: 'offline',
        prompt: 'consent',
        scope: ['openid', 'email', 'profile', 'https://www.googleapis.com/auth/adwords'],
      });
    });

    it('deve retornar uma string', () => {
      oauth2ClientMock.generateAuthUrl.mockReturnValue('https://auth.url');
      const result = service.getAuthUrl();
      expect(typeof result).toBe('string');
    });
  });

  describe('getTokens', () => {
    it('deve retornar tokens válidos quando o Google responder corretamente', async () => {
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

      await expect(service.getTokens('bad-code')).rejects.toThrow('invalid_grant');
    });

    it('deve lançar erro se o código estiver vazio', async () => {
      (oauth2ClientMock.getToken as jest.Mock).mockRejectedValue(new Error('Empty code'));
      await expect(service.getTokens('')).rejects.toThrow('Empty code');
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

    it('deve retornar o payload decodificado corretamente', async () => {
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

    it('deve lançar erro se verifyIdToken rejeitar', async () => {
      (oauth2ClientMock.verifyIdToken as jest.Mock).mockRejectedValue(new Error('invalid token'));
      await expect(service.decodeToken('invalid-token')).rejects.toThrow('invalid token');
    });

    it('deve retornar null se o payload for nulo', async () => {
      const getPayload = jest.fn().mockReturnValue(null);
      (oauth2ClientMock.verifyIdToken as jest.Mock).mockResolvedValue({
        getPayload,
      } as unknown as Auth.LoginTicket);

      const result = await service.decodeToken('token');
      expect(result).toBeNull();
    });
  });

  describe('refreshAccessToken', () => {
    it('deve retornar novo access_token e expiry_date quando sucesso', async () => {
      oauth2ClientMock.credentials.expiry_date = 123456;
      (oauth2ClientMock.getAccessToken as jest.Mock).mockResolvedValue({ token: 'new-token' });

      const result = await service.refreshAccessToken('refresh123');

      expect(result).toEqual({
        access_token: 'new-token',
        expiry_date: 123456,
      });
      expect(oauth2ClientMock.setCredentials).toHaveBeenCalledWith({
        refresh_token: 'refresh123',
      });
    });

    it('deve lançar HttpExceptionCustom se getAccessToken retornar null', async () => {
      (oauth2ClientMock.getAccessToken as jest.Mock).mockResolvedValue(null);

      await expect(service.refreshAccessToken('invalid')).rejects.toThrow(HttpExceptionCustom);
    });

    it('deve lançar erro se getAccessToken rejeitar', async () => {
      (oauth2ClientMock.getAccessToken as jest.Mock).mockRejectedValue(new Error('Google error'));

      await expect(service.refreshAccessToken('refresh-token')).rejects.toThrow('Google error');
    });
  });
});
