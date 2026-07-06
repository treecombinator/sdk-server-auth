/**
 * The auth domain — authentication (who you are).
 * Flows: password (register/login), magic link, password reset — all over JWT sessions.
 * Social login: only the wire contract (`AUTH_ROUTES.social`, `SocialLoginInput`) is declared
 * here — this package does not implement the credential exchange; the BFF must verify the
 * provider credential itself.
 *
 * This package OWNS the auth wire contract below — the DTOs and routes the BFF serves.
 * Client packages declare the same shapes locally, kept in sync with these by convention.
 */

export interface AuthUser {
  id: string;
  email: string;
  createdAt: string;
}

export interface Session {
  /** Signed JWT to put in `Authorization: Bearer`. */
  token: string;
  userId: string;
  expiresAt: string;
}

/**
 * Canonical BFF routes for the auth domain. The server mounts its handlers at these
 * paths and the client calls them — one source of truth, so the two never drift.
 * (`verifySession` is server-internal, so it has no client→BFF route here.)
 */
export const AUTH_ROUTES = {
  register: "/auth/register",
  login: "/auth/login",
  magicLinkStart: "/auth/magic-link",
  magicLinkConsume: "/auth/magic-link/consume",
  passwordResetStart: "/auth/password-reset",
  passwordResetConsume: "/auth/password-reset/consume",
  social: "/auth/social",
} as const;

export type AuthRoute = (typeof AUTH_ROUTES)[keyof typeof AUTH_ROUTES];

/** Social identity providers supported. */
export type SocialProvider = "google" | "apple";

/**
 * What the client POSTs to `AUTH_ROUTES.social`. The credential takes one of two shapes,
 * both verified server-side (the client secret never leaves the BFF):
 *  - `code` (+ `codeVerifier`, `redirectUri`): an OAuth authorization code from a PKCE flow.
 *  - `idToken` (+ `nonce`): an OpenID id_token from a native flow.
 */
export interface SocialLoginInput {
  provider: SocialProvider;
  code?: string;
  codeVerifier?: string;
  redirectUri?: string;
  idToken?: string;
  nonce?: string;
}

export interface Auth {
  register(email: string, password: string): Promise<AuthUser>;
  login(email: string, password: string): Promise<Session>;
  /** Verify a session JWT. Returns the userId or null. Stateless (no DB hit). */
  verifySession(token: string): Promise<{ userId: string } | null>;

  /** Create a one-time magic link and email it (passwordless login). */
  startMagicLink(email: string): Promise<void>;
  /** Consume a magic-link token; returns a session. */
  consumeMagicLink(token: string): Promise<Session>;

  /** Create a password-reset token and email it. No-op signal if email unknown. */
  startPasswordReset(email: string): Promise<void>;
  /** Consume a reset token and set the new password. */
  consumePasswordReset(token: string, newPassword: string): Promise<void>;
}
