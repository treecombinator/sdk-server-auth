import { TcError } from "@treecombinator/sdk-common";
import type { EmailMessage } from "@treecombinator/sdk-server-email";
import type { Auth, AuthUser, Session } from "../port";
import {
  randomId,
  randomToken,
  sha256Hex,
  hashPassword,
  verifyPassword,
  signJwt,
  verifyJwt,
} from "../crypto";

/** DDL — run once during app setup/migration. */
export const AUTH_SCHEMA = `CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  type TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_tokens_user_id ON auth_tokens (user_id);
CREATE INDEX IF NOT EXISTS auth_tokens_expires_at ON auth_tokens (expires_at);`;

/**
 * Structural slice of the Cloudflare D1 binding — only the members this adapter calls,
 * typed minimally so consuming the package does not require @cloudflare/workers-types.
 * A real `D1Database` satisfies it: pass `env.DB` as-is.
 */
export interface D1Statement {
  bind(...values: unknown[]): D1Statement;
  first<T>(): Promise<T | null>;
  run(): Promise<unknown>;
}

export interface D1Binding {
  prepare(query: string): D1Statement;
}

export interface D1AuthConfig {
  db: D1Binding;
  /**
   * Sends the magic-link and password-reset emails — wire `email.send` from the email
   * domain here (or any function with its shape). The contract is the email domain's
   * `EmailMessage`, imported as a TYPE only and inlined into this package's declarations
   * at build: one source of truth for the shape, still zero runtime email dependencies.
   */
  sendEmail: (message: EmailMessage) => Promise<void>;
  /** Secret to sign session JWTs. */
  jwtSecret: string;
  /** Base app URL used to build links, e.g. "https://app.example.com". A trailing slash is fine. */
  appUrl: string;
  /** Session lifetime in seconds (default 7 days). */
  sessionTtlSec?: number;
  /** One-time token lifetime in seconds (default 15 min). */
  tokenTtlSec?: number;
  /** PBKDF2 iterations for password hashing (default 100,000). Changing it invalidates existing hashes. */
  pbkdf2Iterations?: number;
  /** Path under `appUrl` the magic-link email points at (default "/auth/magic"). */
  magicLinkPath?: string;
  /** Path under `appUrl` the password-reset email points at (default "/auth/reset"). */
  passwordResetPath?: string;
}

const EMAIL_SHAPE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MIN_PASSWORD_LENGTH = 8;

const normalizeEmail = (email: string) => email.trim().toLowerCase();

// Well-formed "salt.hash" that matches no password: login burns the same PBKDF2 cost for an
// unknown email as for a wrong password, so response timing doesn't reveal account existence.
const DUMMY_PASSWORD_HASH = `${"A".repeat(22)}.${"A".repeat(43)}`;

interface UserRow {
  id: string;
  email: string;
  password_hash: string | null;
  created_at: string;
}

export function createD1Auth(config: D1AuthConfig): Auth {
  if (new TextEncoder().encode(config.jwtSecret).length < 32) {
    throw new TcError("jwt_secret_weak", "jwtSecret must be at least 32 bytes");
  }
  const sessionTtl = config.sessionTtlSec ?? 604800;
  const tokenTtl = config.tokenTtlSec ?? 900;
  const appUrl = config.appUrl.replace(/\/+$/, "");
  const db = config.db;

  const userByEmail = (email: string) =>
    db.prepare(`SELECT * FROM users WHERE email = ?`).bind(normalizeEmail(email)).first<UserRow>();

  async function issueSession(userId: string): Promise<Session> {
    const token = await signJwt({ sub: userId }, config.jwtSecret, sessionTtl);
    return { token, userId, expiresAt: new Date(Date.now() + sessionTtl * 1000).toISOString() };
  }

  async function createUser(email: string, passwordHash: string | null): Promise<AuthUser> {
    const normalized = normalizeEmail(email);
    if (!EMAIL_SHAPE.test(normalized)) throw new TcError("email_invalid", "not an email address");
    const id = randomId("usr");
    const createdAt = new Date().toISOString();
    try {
      await db
        .prepare(`INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)`)
        .bind(id, normalized, passwordHash, createdAt)
        .run();
    } catch (err) {
      // A concurrent create can hit UNIQUE(email) after the existence check passed.
      if (err instanceof Error && err.message.includes("UNIQUE")) {
        throw new TcError("email_already_registered", "email already registered");
      }
      throw err;
    }
    return { id, email: normalized, createdAt };
  }

  async function mintOneTime(userId: string, type: string): Promise<string> {
    // Opportunistic cleanup: expired tokens are otherwise only removed when consumed.
    await db.prepare(`DELETE FROM auth_tokens WHERE expires_at < ?`).bind(new Date().toISOString()).run();
    const raw = randomToken();
    const expiresAt = new Date(Date.now() + tokenTtl * 1000).toISOString();
    await db
      .prepare(`INSERT INTO auth_tokens (token_hash, user_id, type, expires_at) VALUES (?, ?, ?, ?)`)
      .bind(await sha256Hex(raw), userId, type, expiresAt)
      .run();
    return raw;
  }

  async function consumeOneTime(raw: string, type: string): Promise<string | null> {
    // Atomic consume: with DELETE ... RETURNING, two concurrent consumers race for one row.
    const row = await db
      .prepare(`DELETE FROM auth_tokens WHERE token_hash = ? AND type = ? RETURNING user_id, expires_at`)
      .bind(await sha256Hex(raw), type)
      .first<{ user_id: string; expires_at: string }>();
    if (!row) return null;
    if (new Date(row.expires_at) < new Date()) return null;
    return row.user_id;
  }

  return {
    async register(email, password) {
      if (password.length < MIN_PASSWORD_LENGTH) {
        throw new TcError("password_too_short", `password must be at least ${MIN_PASSWORD_LENGTH} characters`);
      }
      if (await userByEmail(email)) throw new TcError("email_already_registered", "email already registered");
      return createUser(email, await hashPassword(password, config.pbkdf2Iterations));
    },

    async login(email, password) {
      const u = await userByEmail(email);
      // Verify against a dummy hash when there is no user/hash, so both paths cost one PBKDF2.
      const ok = await verifyPassword(password, u?.password_hash ?? DUMMY_PASSWORD_HASH, config.pbkdf2Iterations);
      if (!u || !u.password_hash || !ok) {
        throw new TcError("invalid_credentials", "invalid credentials");
      }
      return issueSession(u.id);
    },

    async verifySession(token) {
      const payload = await verifyJwt(token, config.jwtSecret);
      return payload && typeof payload.sub === "string" ? { userId: payload.sub } : null;
    },

    async startMagicLink(email) {
      const to = normalizeEmail(email);
      // Passwordless signup by design: an unknown (shape-valid) email gets a user created here.
      const u = (await userByEmail(to)) ?? { id: (await createUser(to, null)).id };
      const raw = await mintOneTime(u.id, "magic");
      const link = `${appUrl}${config.magicLinkPath ?? "/auth/magic"}?token=${raw}`;
      await config.sendEmail({
        to,
        subject: "Your sign-in link",
        text: `Sign in: ${link}`,
        html: `<p><a href="${link}">Sign in</a></p>`,
      });
    },

    async consumeMagicLink(token) {
      const userId = await consumeOneTime(token, "magic");
      if (!userId) throw new TcError("magic_link_invalid", "invalid or expired link");
      return issueSession(userId);
    },

    async startPasswordReset(email) {
      const u = await userByEmail(email);
      if (!u) return; // don't reveal whether the email exists
      const raw = await mintOneTime(u.id, "reset");
      const link = `${appUrl}${config.passwordResetPath ?? "/auth/reset"}?token=${raw}`;
      await config.sendEmail({
        to: u.email,
        subject: "Reset your password",
        text: `Reset your password: ${link}`,
        html: `<p><a href="${link}">Reset your password</a></p>`,
      });
    },

    async consumePasswordReset(token, newPassword) {
      // Validate the new password before consuming, so a policy rejection doesn't burn the token.
      if (newPassword.length < MIN_PASSWORD_LENGTH) {
        throw new TcError("password_too_short", `password must be at least ${MIN_PASSWORD_LENGTH} characters`);
      }
      const userId = await consumeOneTime(token, "reset");
      if (!userId) throw new TcError("reset_token_invalid", "invalid or expired token");
      await db.prepare(`UPDATE users SET password_hash = ? WHERE id = ?`).bind(await hashPassword(newPassword, config.pbkdf2Iterations), userId).run();
      // A reset revokes every other outstanding one-time token for the user (magic links and
      // older resets). Already-issued session JWTs stay valid until `exp` — see README Notes.
      await db.prepare(`DELETE FROM auth_tokens WHERE user_id = ?`).bind(userId).run();
    },
  };
}
