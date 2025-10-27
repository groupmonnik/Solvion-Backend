import { Test, TestingModule } from "@nestjs/testing";
import { MetaAuthController } from "@/integrations/meta/meta.accounts.controller";
import { MetaAuthService } from "@/integrations/meta/meta.accounts.service";
import { UnauthorizedException } from "@nestjs/common";
import type { FastifyReply } from "fastify";

describe("MetaAuthController", () => {
  let controller: MetaAuthController;
  let metaAuthService: jest.Mocked<MetaAuthService>;
  let mockReply: jest.Mocked<FastifyReply>;

  beforeEach(async () => {
    metaAuthService = {
      getAuthUrl: jest.fn(),
      getTokens: jest.fn(),
    } as unknown as jest.Mocked<MetaAuthService>;

    mockReply = {
      redirect: jest.fn(),
      send: jest.fn(),
    } as unknown as jest.Mocked<FastifyReply>;

    const module: TestingModule = await Test.createTestingModule({
      controllers: [MetaAuthController],
      providers: [
        {
          provide: MetaAuthService,
          useValue: metaAuthService,
        },
      ],
    }).compile();

    controller = module.get<MetaAuthController>(MetaAuthController);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("redirectToMeta", () => {
    it("deve redirecionar para a URL retornada pelo service", () => {
      const mockUrl = "https://facebook.com/oauth";
      metaAuthService.getAuthUrl.mockReturnValue(mockUrl);

      const action = () => controller.redirectToMeta(mockReply);
      action();
      const reply = mockReply.redirect;
      const getAuthUrl = metaAuthService.getAuthUrl;
      expect(getAuthUrl).toHaveBeenCalledTimes(1);
      expect(reply).toHaveBeenCalledWith(mockUrl, 302);
    });
  });

  describe("metaCallback", () => {
    it("deve retornar RedirectResponse quando o código for válido", async () => {
      const mockCode = "abc123";
      const mockTokens = { token: "token-xyz", expires_at: new Date() };
      metaAuthService.getTokens.mockResolvedValue(mockTokens);

      const expectedResponse = {
        statusCode: 200,
        message: "redirection and collection of tokens done successfully",
        success: true,
        data: null,
      };

      const result = await controller.metaCallback(mockCode);
      const getToken = metaAuthService.getTokens;

      expect(getToken).toHaveBeenCalledWith(mockCode);
      expect(result).toEqual(expectedResponse);
    });

    it("deve lançar UnauthorizedException se o code estiver vazio", async () => {
      const action = controller.metaCallback("");
      await expect(action).rejects.toThrow(UnauthorizedException);
    });

    it("deve propagar erro do MetaAuthService se getTokens falhar", async () => {
      metaAuthService.getTokens.mockRejectedValue(
        new Error("Erro ao pegar token"),
      );

      const action = controller.metaCallback("bad-code");
      await expect(action).rejects.toThrow("Erro ao pegar token");
    });
  });
});
