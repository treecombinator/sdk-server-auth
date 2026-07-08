# @treecombinator/sdk-server-auth

---

> Developed by Danthur Lice.\
> Copyright © 2026 Tree Combinator.\
> Contact: dev (at) treecombinator.com

---

The **auth** domain of the Tree Combinator SDK — registration, login and session verification on Cloudflare D1 with Web Crypto (JWT/PBKDF2), plus magic-link and password-reset flows. It owns the auth wire contract the client consumes, and takes an injected `sendEmail` function for its mails — depending only on `@treecombinator/sdk-common` for the error type.

## Install

```bash
givo add @treecombinator/sdk-server-auth
```

## Use

```ts
import { createAuth, AUTH_SCHEMA } from "@treecombinator/sdk-server-auth";

// run AUTH_SCHEMA once as a D1 migration, then:
const auth = createAuth({
  db: env.DB,
  jwtSecret: env.JWT_SECRET,
  appUrl: "https://app.example.com",
  sendEmail: (msg) => email.send(msg), // wire your email adapter here
});

const user = await auth.register("a@b.com", "pw");
const session = await auth.login("a@b.com", "pw"); // { token, userId, expiresAt }
```

`createAuth(config)` returns the auth API:

- `register(email, password)` / `login(email, password)` — password auth; `login` returns a `Session`.
- `verifySession(token)` — stateless JWT check → `{ userId }` or `null`.
- `startMagicLink(email)` / `consumeMagicLink(token)` — passwordless login. An unknown (shape-valid) email gets a user created here: magic link doubles as passwordless signup.
- `startPasswordReset(email)` / `consumePasswordReset(token, newPassword)` — reset flow. Consuming a reset also revokes every other outstanding one-time token for the user.

Config: `{ db, jwtSecret, appUrl, sendEmail, sessionTtlSec?, tokenTtlSec?, pbkdf2Iterations?, magicLinkPath?, passwordResetPath? }`. `magicLinkPath`/`passwordResetPath` are the `appUrl` paths the emails point at (defaults `/auth/magic` and `/auth/reset`). The package also exports the wire contract it owns (`AuthUser`, `Session`, `AUTH_ROUTES`, `SocialProvider`, `SocialLoginInput`) — client packages keep local copies of these shapes in sync with it — and the `AUTH_SCHEMA` DDL.

### Wire (BFF boundary)

The BFF mounts one handler per `AUTH_ROUTES` entry. Request bodies and success responses:

| Route | Request body | Success |
| --- | --- | --- |
| `AUTH_ROUTES.register` | `{ email, password }` | `AuthUser` |
| `AUTH_ROUTES.login` | `{ email, password }` | `Session` |
| `AUTH_ROUTES.magicLinkStart` | `{ email }` | empty (204) |
| `AUTH_ROUTES.magicLinkConsume` | `{ token }` | `Session` |
| `AUTH_ROUTES.passwordResetStart` | `{ email }` | empty (204) |
| `AUTH_ROUTES.passwordResetConsume` | `{ token, newPassword }` | empty (204) |
| `AUTH_ROUTES.social` | `SocialLoginInput` | `Session` — route declared only; this package does not implement the exchange |

On failure, serialize `TcError.toJSON()` (`{ error, details? }`) with these statuses:

| Code | Status |
| --- | --- |
| `invalid_credentials` | 401 |
| `email_already_registered` | 409 |
| `email_invalid`, `password_too_short`, `magic_link_invalid`, `reset_token_invalid` | 400 |
| anything unexpected | 500 |

Reserve 401 on other routes for a dead/absent session (e.g. a code like `session_expired` when `verifySession` returns `null`) — the client http hook `onUnauthorized(code)` keys off the code to decide whether to drop the stored session.

## Notes

- Errors are `TcError` with specific codes: `email_already_registered`, `email_invalid`, `password_too_short`, `invalid_credentials`, `magic_link_invalid`, `reset_token_invalid`, `jwt_secret_weak`.
- `sendEmail` is injected — the app wires its own email adapter; this package has no email dependency.
- Emails are normalized (trim + lowercase) everywhere; passwords must be at least 8 characters (`register` and `consumePasswordReset`).
- `jwtSecret` must be at least 32 bytes — `createAuth` throws `jwt_secret_weak` otherwise.
- Session JWTs are verified statelessly, so a password reset cannot revoke ones already issued: they stay valid until `exp`. Size `sessionTtlSec` (default 7 days) with that window in mind.
- `pbkdf2Iterations` defaults to 100,000 — deliberately below OWASP's 600,000 to fit a Worker's CPU budget; raise it via config if your platform allows. Changing it invalidates existing password hashes.
