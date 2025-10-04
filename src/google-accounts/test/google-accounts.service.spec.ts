import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { GoogleAccountsService } from '@/google-accounts/google-accounts.service';
import { GoogleTokensResponse } from '../types/service/return/google-tokens-response-return';
import { GoogleTokenIdResponse } from '../types/service/return/google-tokens-id-response-return';
import { decode } from 'jsonwebtoken';
import axios from 'axios';
import { HttpExceptionCustom } from '@/common/exceptions/custom/custom.exception';

jest.mock('axios');
jest.mock('jsonwebtoken');
let mockedAxios: jest.Mocked<typeof axios>;
let mockedDecode: jest.MockedFunction<typeof decode>;

describe('GoogleAccountsService - getAuthUrl', () => {
  let service: GoogleAccountsService;

  const mockConfigService = {
    get: (key: string) => {
      const values: Record<string, string> = {
        GOOGLE_CLIENT_ID: 'test-client-id',
        GOOGLE_CLIENT_SECRET: 'test-client-secret',
        GOOGLE_REDIRECT_URI: 'http://localhost/callback',
        GOOGLE_TOKEN_URI: 'https://oauth2.googleapis.com/token',
      };
      return values[key];
    },
  };

  beforeAll(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [GoogleAccountsService, { provide: ConfigService, useValue: mockConfigService }],
    }).compile();

    service = module.get<GoogleAccountsService>(GoogleAccountsService);
  });

  beforeEach(() => {
    jest.clearAllMocks();
    mockedAxios = axios as jest.Mocked<typeof axios>;
    mockedDecode = decode as jest.MockedFunction<typeof decode>;
  });

  describe('getAuthUrl', () => {
    const expectedUrl =
      'https://accounts.google.com/o/oauth2/v2/auth?' +
      'response_type=code&' +
      'client_id=test-client-id&' +
      'redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&' +
      'scope=openid+email+profile+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fadwords&' +
      'access_type=offline&' +
      'prompt=select_account';

    it('1 - should build URL in correct order with correct values', () => {
      const url = service.getAuthUrl();
      expect(url).toBe(expectedUrl);
    });

    it('2 - should not match if values are wrong but order is correct', () => {
      const wrongValuesUrl =
        'https://accounts.google.com/o/oauth2/v2/auth?' +
        'response_type=code&' +
        'client_id=wrong-client-id&' + // valor errado
        'redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&' +
        'scope=openid+email+profile+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fadwords&' +
        'access_type=offline&' +
        'prompt=select_account';

      const url = service.getAuthUrl();
      expect(url).not.toBe(wrongValuesUrl);
    });

    it('3 - should not match if values are correct but order is wrong', () => {
      const wrongOrderUrl =
        'https://accounts.google.com/o/oauth2/v2/auth?' +
        'client_id=test-client-id&' + // ordem trocada
        'response_type=code&' +
        'redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&' +
        'scope=openid+email+profile+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fadwords&' +
        'access_type=offline&' +
        'prompt=select_account';

      const url = service.getAuthUrl();
      expect(url).not.toBe(wrongOrderUrl);
    });

    it('4 - should not match if values and order are wrong', () => {
      const completelyWrongUrl =
        'https://accounts.google.com/o/oauth2/v2/auth?' +
        'client_id=wrong-client-id&' +
        'response_type=wrong&' +
        'redirect_uri=wrong-uri&' +
        'scope=wrong-scope&' +
        'access_type=wrong&' +
        'prompt=wrong';

      const url = service.getAuthUrl();
      expect(url).not.toBe(completelyWrongUrl);
    });
  });

  describe('getTokens', () => {
    it('1 - should return GoogleTokensResponse on success', async () => {
      const fakeResponse: GoogleTokensResponse = {
        access_token: 'fake-access-token',
        expires_in: 3600,
        refresh_token: 'fake-refresh-token',
        scope: 'openid email profile',
        token_type: 'Bearer',
        id_token: 'fake-id-token',
      };
      const postSpyOn = jest.spyOn(mockedAxios, 'post');
      mockedAxios.post.mockResolvedValue({ data: fakeResponse });

      const result = await service.getTokens('valid-code');
      expect(result).toEqual(fakeResponse);
      expect(postSpyOn).toHaveBeenCalledTimes(1);
    });

    it('2 - should throw if axios returns an error (HTTP error)', async () => {
      const postSpyOn = jest.spyOn(mockedAxios, 'post');
      mockedAxios.post.mockRejectedValue({
        response: { status: 400, data: { error: 'invalid_grant' } },
      });

      await expect(service.getTokens('invalid-code')).rejects.toMatchObject({
        response: { data: { error: 'invalid_grant' } },
      });
      expect(postSpyOn).toHaveBeenCalledTimes(1);
    });

    it('3 - should throw if code is empty', async () => {
      const postSpyOn = jest.spyOn(mockedAxios, 'post');
      mockedAxios.post.mockRejectedValue({
        response: { status: 400, data: { error: 'invalid_grant' } },
      });

      await expect(service.getTokens('')).rejects.toMatchObject({
        response: { data: { error: 'invalid_grant' } },
      });
      expect(postSpyOn).toHaveBeenCalledTimes(1);
    });

    it('4 - should throw if axios throws network error', async () => {
      const postSpyOn = jest.spyOn(mockedAxios, 'post');
      mockedAxios.post.mockRejectedValue(new Error('Network Error'));

      await expect(service.getTokens('any-code')).rejects.toThrow(
        'Erro de rede ou infraestrutura ao tentar a comunicação com o Google.',
      );
      expect(postSpyOn).toHaveBeenCalledTimes(1);
    });

    it('6 - should send correct payload to axios', async () => {
      const fakeResponse: GoogleTokensResponse = {
        access_token: 'fake-access-token',
        expires_in: 3600,
        refresh_token: 'fake-refresh-token',
        scope: 'openid email profile',
        token_type: 'Bearer',
        id_token: 'fake-id-token',
      };
      const postSpyOn = jest.spyOn(mockedAxios, 'post');
      mockedAxios.post.mockResolvedValue({ data: fakeResponse });

      const code = 'test-code';
      await service.getTokens(code);

      expect(postSpyOn).toHaveBeenCalledWith(
        'https://oauth2.googleapis.com/token',
        expect.stringContaining(`code=${code}`),
        expect.objectContaining({
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        }),
      );

      const calledPayload = mockedAxios.post.mock.calls[0][1];
      expect(calledPayload).toContain('client_id=test-client-id');
      expect(calledPayload).toContain('client_secret=test-client-secret');
      expect(calledPayload).toContain('redirect_uri=http%3A%2F%2Flocalhost%2Fcallback');
      expect(calledPayload).toContain('grant_type=authorization_code');
    });
  });

  describe('decodeToken', () => {
    it('1 - should return decoded token with all fields when valid', () => {
      const fakeDecoded: GoogleTokenIdResponse = {
        iss: 'accounts.google.com',
        aud: 'test-client-id',
        azp: 'test-client-id',
        sub: '123456789',
        email: 'test@example.com',
        email_verified: true,
        name: 'Test User',
        picture: 'http://example.com/pic.jpg',
        given_name: 'Test',
        family_name: 'User',
        locale: 'en',
        iat: 1234567890,
        exp: 1234569999,
      };

      mockedDecode.mockReturnValue(fakeDecoded);

      const result = service.decodeToken('valid-token');
      expect(result).toEqual(fakeDecoded);
      expect(mockedDecode).toHaveBeenCalledWith('valid-token');
    });

    it('2 - should throw HttpExceptionCustom when decode returns null', () => {
      mockedDecode.mockReturnValue(null);

      expect(() => service.decodeToken('invalid-token')).toThrow(HttpExceptionCustom);
      expect(mockedDecode).toHaveBeenCalledWith('invalid-token');
    });

    it('3 - should return object with undefined values if decode result is partial', () => {
      const partialDecoded = {
        iss: 'accounts.google.com',
        aud: 'test-client-id',
        sub: '123456789',
        email: 'test@example.com',
        email_verified: true,
      };

      mockedDecode.mockReturnValue(partialDecoded);

      const result = service.decodeToken('partial-token');
      expect(result).toEqual({
        iss: 'accounts.google.com',
        aud: 'test-client-id',
        azp: undefined,
        sub: '123456789',
        email: 'test@example.com',
        email_verified: true,
        name: undefined,
        picture: undefined,
        given_name: undefined,
        family_name: undefined,
        locale: undefined,
        iat: undefined,
        exp: undefined,
      });
    });

    it('4 - should ignore extra fields and return only defined properties', () => {
      const decodedWithExtras = {
        iss: 'accounts.google.com',
        aud: 'test-client-id',
        sub: '123456789',
        email: 'test@example.com',
        email_verified: true,
        name: 'Extra User',
        picture: 'http://example.com/pic.jpg',
        iat: 1234567890,
        exp: 1234569999,
        extra_field: 'ignore-me',
      };

      mockedDecode.mockReturnValue(decodedWithExtras);

      const result = service.decodeToken('extra-token');
      expect(result).toEqual({
        iss: 'accounts.google.com',
        aud: 'test-client-id',
        azp: undefined,
        sub: '123456789',
        email: 'test@example.com',
        email_verified: true,
        name: 'Extra User',
        picture: 'http://example.com/pic.jpg',
        given_name: undefined,
        family_name: undefined,
        locale: undefined,
        iat: 1234567890,
        exp: 1234569999,
      });
      expect('extra_field' in result).toBe(false);
    });

    it('5 - should return object even if fields have unexpected types', () => {
      const decodedWithWrongTypes = {
        iss: 'accounts.google.com',
        aud: 'test-client-id',
        sub: '123456789',
        email: 'test@example.com',
        email_verified: 'true',
        name: 12345,
        iat: 'not-a-number',
        exp: 'not-a-number',
      };

      mockedDecode.mockReturnValue(decodedWithWrongTypes as any);

      const result = service.decodeToken('wrong-types-token');
      expect(result).toEqual({
        iss: 'accounts.google.com',
        aud: 'test-client-id',
        azp: undefined,
        sub: '123456789',
        email: 'test@example.com',
        email_verified: 'true',
        name: 12345,
        picture: undefined,
        given_name: undefined,
        family_name: undefined,
        locale: undefined,
        iat: 'not-a-number',
        exp: 'not-a-number',
      });
    });
  });
});
