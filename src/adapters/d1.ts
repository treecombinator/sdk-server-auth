import { TcError } from "@treecombinator/sdk-common";
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
);`;

/** The email this domain asks the app to send (magic link / password reset). */
export interface AuthEmail {
  to: string;
  subject: string;
  text: string;
  html: string;
}

export interface D1AuthConfig {
  db: D1Database;
  /** Sends the magic-link and password-reset emails — the app wires its email adapter here. */
  sendEmail: (message: AuthEmail) => Promise<void>;
  /** Secret to sign session JWTs. */
  jwtSecret: string;
  /** Base app URL used to build links, e.g. "https://app.example.com". */
  appUrl: string;
  /** Session lifetime in seconds (default 7 days). */
  sessionTtlSec?: number;
  /** One-time token lifetime in seconds (default 15 min). */
  tokenTtlSec?: number;
  /** PBKDF2 iterations for password hashing (default 100,000). Changing it invalidates existing hashes. */
  pbkdf2Iterations?: number;
}

interface UserRow {
  id: string;
  email: string;
  password_hash: string | null;
  created_at: string;
}

export function createD1Auth(config: D1AuthConfig): Auth {
  const sessionTtl = config.sessionTtlSec ?? 604800;
  const tokenTtl = config.tokenTtlSec ?? 900;
  const db = config.db;

  const userByEmail = (email: string) =>
    db.prepare(`SELECT * FROM users WHERE email = ?`).bind(email.toLowerCase()).first<UserRow>();

  async function issueSession(userId: string): Promise<Session> {
    const token = await signJwt({ sub: userId }, config.jwtSecret, sessionTtl);
    return { token, userId, expiresAt: new Date(Date.now() + sessionTtl * 1000).toISOString() };
  }

  async function createUser(email: string, passwordHash: string | null): Promise<AuthUser> {
    const id = randomId("usr");
    const createdAt = new Date().toISOString();
    await db
      .prepare(`INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)`)
      .bind(id, email.toLowerCase(), passwordHash, createdAt)
      .run();
    return { id, email: email.toLowerCase(), createdAt };
  }

  async function mintOneTime(userId: string, type: string): Promise<string> {
    const raw = randomToken();
    const expiresAt = new Date(Date.now() + tokenTtl * 1000).toISOString();
    await db
      .prepare(`INSERT INTO auth_tokens (token_hash, user_id, type, expires_at) VALUES (?, ?, ?, ?)`)
      .bind(await sha256Hex(raw), userId, type, expiresAt)
      .run();
    return raw;
  }

  async function consumeOneTime(raw: string, type: string): Promise<string | null> {
    const hash = await sha256Hex(raw);
    const row = await db
      .prepare(`SELECT user_id, expires_at FROM auth_tokens WHERE token_hash = ? AND type = ?`)
      .bind(hash, type)
      .first<{ user_id: string; expires_at: string }>();
    if (!row) return null;
    await db.prepare(`DELETE FROM auth_tokens WHERE token_hash = ?`).bind(hash).run(); // one-time use
    if (new Date(row.expires_at) < new Date()) return null;
    return row.user_id;
  }

  return {
    async register(email, password) {
      if (await userByEmail(email)) throw new TcError("email_already_registered", "email already registered");
      return createUser(email, await hashPassword(password, config.pbkdf2Iterations));
    },

    async login(email, password) {
      const u = await userByEmail(email);
      if (!u || !u.password_hash || !(await verifyPassword(password, u.password_hash, config.pbkdf2Iterations))) {
        throw new TcError("invalid_credentials", "invalid credentials");
      }
      return issueSession(u.id);
    },

    async verifySession(token) {
      const payload = await verifyJwt(token, config.jwtSecret);
      return payload && typeof payload.sub === "string" ? { userId: payload.sub } : null;
    },

    async startMagicLink(email) {
      const u = (await userByEmail(email)) ?? { id: (await createUser(email, null)).id };
      const raw = await mintOneTime(u.id, "magic");
      const link = `${config.appUrl}/auth/magic?token=${raw}`;
      await config.sendEmail({
        to: email.toLowerCase(),
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
      const link = `${config.appUrl}/auth/reset?token=${raw}`;
      await config.sendEmail({
        to: u.email,
        subject: "Reset your password",
        text: `Reset your password: ${link}`,
        html: `<p><a href="${link}">Reset your password</a></p>`,
      });
    },

    async consumePasswordReset(token, newPassword) {
      const userId = await consumeOneTime(token, "reset");
      if (!userId) throw new TcError("reset_token_invalid", "invalid or expired token");
      await db.prepare(`UPDATE users SET password_hash = ? WHERE id = ?`).bind(await hashPassword(newPassword, config.pbkdf2Iterations), userId).run();
    },
  };
}
