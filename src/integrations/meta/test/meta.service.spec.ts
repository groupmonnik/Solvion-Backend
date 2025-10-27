import { ConfigService } from "@nestjs/config";
import { MetaAuthService } from "@/integrations/meta/meta.accounts.service";
import { AuthorizationCode } from "simple-oauth2";

jest.mock("simple-oauth2", () => ({
  AuthorizationCode: jest.fn().mockImplementation(() => ({
    authorizeURL: jest.fn(),
    getToken: jest.fn(),
  })),
}));

describe("MetaAuthService", () => {
  let service: MetaAuthService;
  let configService: jest.Mocked<ConfigService>;
  let mockAuthorizeURL: jest.Mock;
  let mockGetToken: jest.Mock;

  beforeEach(() => {
    configService = {
      get: jest.fn((key: string) => {
        const configMap: Record<string, string> = {
          FB_APP_ID: "test-app-id",
          FB_APP_SECRET: "test-app-secret",
          FB_REDIRECT_URI: "https://redirect.uri",
          FB_SCOPES: "email,public_profile",
        };
        return configMap[key];
      }),
    } as unknown as jest.Mocked<ConfigService>;

    mockAuthorizeURL = jest.fn();
    mockGetToken = jest.fn();

    (AuthorizationCode as jest.Mock).mockImplementation(() => ({
      authorizeURL: mockAuthorizeURL,
      getToken: mockGetToken,
    }));

    service = new MetaAuthService(configService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("constructor", () => {
    it("deve criar o cliente OAuth2 com as configs corretas", () => {
      expect(AuthorizationCode).toHaveBeenCalledWith({
        client: {
          id: "test-app-id",
          secret: "test-app-secret",
        },
        auth: {
          tokenHost: "https://graph.facebook.com",
          tokenPath: "/v24.0/oauth/access_token",
          authorizeHost: "https://www.facebook.com",
          authorizePath: "/v24.0/dialog/oauth",
        },
      });
    });
  });

  describe("getAuthUrl", () => {
    it("deve retornar a URL gerada pelo authorizeURL com os parâmetros corretos", () => {
      mockAuthorizeURL.mockReturnValue("https://facebook.com/oauth?code=123");

      const result = service.getAuthUrl();

      expect(configService.get).toHaveBeenCalledWith("FB_REDIRECT_URI");
      expect(configService.get).toHaveBeenCalledWith("FB_SCOPES");
      expect(mockAuthorizeURL).toHaveBeenCalledWith({
        redirect_uri: "https://redirect.uri",
        scope: "email,public_profile",
        response_type: "code",
        auth_type: "reauthenticate",
      });
      expect(result).toBe("https://facebook.com/oauth?code=123");
    });

    it("deve propagar erro se authorizeURL lançar exceção", () => {
      mockAuthorizeURL.mockImplementation(() => {
        throw new Error("mocked failure");
      });

      expect(() => service.getAuthUrl()).toThrow("mocked failure");
    });
  });

  describe("getTokens", () => {
    it("deve chamar getToken com os parâmetros corretos e retornar o token e expires_at", async () => {
      const fakeDate = new Date();
      const mockToken = {
        token: { access_token: "abc123", expires_at: fakeDate },
      };
      mockGetToken.mockResolvedValue(mockToken);

      const result = await service.getTokens("auth-code-xyz");

      expect(configService.get).toHaveBeenCalledWith("FB_REDIRECT_URI");
      expect(mockGetToken).toHaveBeenCalledWith({
        code: "auth-code-xyz",
        redirect_uri: "https://redirect.uri",
      });

      expect(result).toEqual({
        token: "abc123",
        expires_at: fakeDate,
      });

      expect(result.expires_at.getTime()).toBe(fakeDate.getTime());
    });

    it("deve lançar erro personalizado se getToken falhar", async () => {
      mockGetToken.mockRejectedValue(new Error("Error da Meta"));
      const token = service.getTokens("code-fail");
      await expect(token).rejects.toThrow("Error da Meta");
    });

    it("deve lançar erro se o código for vazio", async () => {
      mockGetToken.mockRejectedValue(new Error("invalid code"));
      const token = service.getTokens("");
      await expect(token).rejects.toThrow("invalid code");
    });
  });
});
