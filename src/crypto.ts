/** Crypto helpers for auth — Web Crypto only (Workers-native). */

function bytesToB64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const strToB64url = (s: string): string => bytesToB64url(new TextEncoder().encode(s));
const b64urlToStr = (s: string): string => new TextDecoder().decode(b64urlToBytes(s));

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function randomId(prefix: string): string {
  const b = new Uint8Array(12);
  crypto.getRandomValues(b);
  return `${prefix}_${bytesToB64url(b)}`;
}

export function randomToken(): string {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return bytesToB64url(b);
}

export async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

/** PBKDF2 iterations used when none is configured. Conservative so it stays within a Worker's CPU budget. */
const DEFAULT_PBKDF2_ITERATIONS = 100_000;

async function pbkdf2(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, key, 256);
  return new Uint8Array(bits);
}

/** "salt.hash" (both base64url). `iterations` must match at verify time. */
export async function hashPassword(password: string, iterations = DEFAULT_PBKDF2_ITERATIONS): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, iterations);
  return `${bytesToB64url(salt)}.${bytesToB64url(hash)}`;
}

export async function verifyPassword(password: string, stored: string, iterations = DEFAULT_PBKDF2_ITERATIONS): Promise<boolean> {
  const parts = stored.split(".");
  if (parts.length !== 2) return false;
  const saltB = parts[0]!;
  const hashB = parts[1]!;
  try {
    const hash = await pbkdf2(password, b64urlToBytes(saltB), iterations);
    return timingSafeEqual(bytesToB64url(hash), hashB);
  } catch {
    return false; // malformed stored hash (e.g. salt that isn't base64url)
  }
}

async function hmacSha256(secret: string, data: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data)));
}

/** Sign a JWT (HS256) with the given payload + ttl. */
export async function signJwt(payload: Record<string, unknown>, secret: string, ttlSec: number): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = strToB64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = strToB64url(JSON.stringify({ ...payload, iat: now, exp: now + ttlSec }));
  const data = `${header}.${body}`;
  const sig = bytesToB64url(await hmacSha256(secret, data));
  return `${data}.${sig}`;
}

/** Verify a JWT (HS256). Returns the payload or null (bad signature / expired). */
export async function verifyJwt(token: string, secret: string): Promise<Record<string, unknown> | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const h = parts[0]!;
  const b = parts[1]!;
  const s = parts[2]!;
  const expected = bytesToB64url(await hmacSha256(secret, `${h}.${b}`));
  if (!timingSafeEqual(expected, s)) return null;
  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(b64urlToStr(b)) as Record<string, unknown>;
  } catch {
    return null;
  }
  const exp = payload.exp;
  if (typeof exp === "number" && exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}
