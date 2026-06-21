import type { Auth } from "./port";
import { createD1Auth, type D1AuthConfig } from "./adapters/d1";

export type { Auth, AuthUser, Session, AuthRoute, SocialProvider, SocialLoginInput } from "./port";
export { AUTH_ROUTES } from "./port";
export type { D1AuthConfig, AuthEmail } from "./adapters/d1";
export { AUTH_SCHEMA } from "./adapters/d1";

/**
 * Auth domain factory. Adapter: Cloudflare D1 + Web Crypto (JWT/PBKDF2); the app injects a
 * `sendEmail` function for the magic-link and password-reset mails.
 */
export function createAuth(config: D1AuthConfig): Auth {
  return createD1Auth(config);
}
