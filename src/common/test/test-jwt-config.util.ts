/**
 * Test JWT Configuration Utility
 *
 * Provides reusable JWT and crypto configurations for integration tests.
 * Sets up environment variables and returns configuration objects.
 */

export type TestJwtConfiguration = {
  accessToken: {
    secret: string;
    expiresIn: string;
  };
  refreshToken: {
    secret: string;
    expiresIn: string;
  };
  crypto: {
    key: string;
  };
  cookie: {
    secret: string;
  };
};

export type TestJwtDefaults = {
  accessTokenSecret?: string;
  accessTokenExpiresIn?: string;
  refreshTokenSecret?: string;
  refreshTokenExpiresIn?: string;
  cryptoKey?: string;
  cookieSecret?: string;
};

const DEFAULT_TEST_CONFIG: Required<TestJwtDefaults> = {
  accessTokenSecret: 'test-access-secret',
  accessTokenExpiresIn: '3600s',
  refreshTokenSecret: 'test-refresh-secret',
  refreshTokenExpiresIn: '7d',
  cryptoKey: '10356586236241190c99852c49c3970e6e7b1f2f0f4a88cfe99bbfd3e61e4bd1',
  cookieSecret: 'test-cookie-secret',
};

/**
 * Setup test JWT configuration
 *
 * Configures environment variables and returns configuration objects
 * for JWT tokens, crypto, and cookies in integration tests.
 *
 * @param customConfig - Optional custom configuration to override defaults
 * @returns Configuration object with all JWT and crypto settings
 *
 * @example
 * ```typescript
 * const testConfig = setupTestJwtConfig();
 *
 * // Use in TestingModule
 * const module = await Test.createTestingModule({
 *   providers: [
 *     {
 *       provide: 'CONFIGURATION(accessTokenJwt)',
 *       useValue: testConfig.accessToken,
 *     },
 *     {
 *       provide: 'CONFIGURATION(refreshTokenJwt)',
 *       useValue: testConfig.refreshToken,
 *     },
 *   ],
 * }).compile();
 *
 * // Use in Fastify
 * app.register(cookieParser as any, { secret: testConfig.cookie.secret });
 * ```
 */
export function setupTestJwtConfig(customConfig: TestJwtDefaults = {}): TestJwtConfiguration {
  const config = {
    ...DEFAULT_TEST_CONFIG,
    ...customConfig,
  };

  // Set environment variables
  process.env.ACCESS_TOKEN_JWT_KEY = config.accessTokenSecret;
  process.env.ACCESS_TOKEN_JWT_EXPIRES_IN = config.accessTokenExpiresIn;
  process.env.REFRESH_TOKEN_JWT_KEY = config.refreshTokenSecret;
  process.env.REFRESH_TOKEN_JWT_EXPIRES_IN = config.refreshTokenExpiresIn;
  process.env.CRYPTO_KEY = config.cryptoKey;

  return {
    accessToken: {
      secret: config.accessTokenSecret,
      expiresIn: config.accessTokenExpiresIn,
    },
    refreshToken: {
      secret: config.refreshTokenSecret,
      expiresIn: config.refreshTokenExpiresIn,
    },
    crypto: {
      key: config.cryptoKey,
    },
    cookie: {
      secret: config.cookieSecret,
    },
  };
}

/**
 * Clear test JWT environment variables
 *
 * Removes all JWT-related environment variables set by setupTestJwtConfig.
 * Should be called in afterAll() to clean up test environment.
 *
 * @example
 * ```typescript
 * afterAll(() => {
 *   clearTestJwtConfig();
 * });
 * ```
 */
export function clearTestJwtConfig(): void {
  delete process.env.ACCESS_TOKEN_JWT_KEY;
  delete process.env.ACCESS_TOKEN_JWT_EXPIRES_IN;
  delete process.env.REFRESH_TOKEN_JWT_KEY;
  delete process.env.REFRESH_TOKEN_JWT_EXPIRES_IN;
  delete process.env.CRYPTO_KEY;
}
