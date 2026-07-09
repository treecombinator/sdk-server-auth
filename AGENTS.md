# AGENTS.md — @treecombinator/sdk-server-auth

Auth (authentication) domain of the Tree Combinator SDK for Cloudflare Workers. D1 + Web Crypto (JWT/PBKDF2). The app injects a `sendEmail` function for the magic-link and password-reset mails. Run `AUTH_SCHEMA` once.

## Use

```ts
import { createAuth, AUTH_SCHEMA } from "@treecombinator/sdk-server-auth";

const auth = createAuth({
  db: env.DB,
  jwtSecret,
  appUrl: "https://app.example.com",
  sendEmail: (m) => myEmailAdapter.send(m), // the app wires its email here
});
const session = await auth.login(email, password);
```

`createAuth({ db, jwtSecret, appUrl, sendEmail, sessionTtlSec?, tokenTtlSec?, pbkdf2Iterations?, magicLinkPath?, passwordResetPath? })` →
`register`, `login`, `verifySession`, `startMagicLink`/`consumeMagicLink`,
`startPasswordReset`/`consumePasswordReset`. DDL: `AUTH_SCHEMA`.

## Notes

- This package OWNS the auth wire contract: `AuthUser`, `Session`, `AUTH_ROUTES`, `AuthRoute`, `SocialProvider`, `SocialLoginInput`. Client packages declare the same shapes locally, kept in sync with these by convention (see README "Wire" for body shapes and status mapping).
- `AUTH_ROUTES.social` is contract only — this package implements no social credential exchange.
- Email is an injected `sendEmail(message)` function; the message contract is the email domain's `EmailMessage`, imported as a TYPE only and inlined into the declarations (zero runtime dependency on sdk-server-email).
- Errors are `TcError` (from `@treecombinator/sdk-common`) with specific codes: `email_already_registered`, `email_invalid`, `password_too_short`, `invalid_credentials`, `magic_link_invalid`, `reset_token_invalid`, `jwt_secret_weak`.
- Password `register` accepts a shape-valid email unverified; verified-email signup is the magic-link flow. `startMagicLink` creates a user for an unknown (shape-valid) email — passwordless signup by design. `consumePasswordReset` revokes all of the user's outstanding one-time tokens; already-issued session JWTs stay valid until `exp` (stateless verification).
- `db` is a structural slice of the D1 binding (`D1Binding`: `prepare`/`bind`/`first`/`run`) — consumers don't need `@cloudflare/workers-types`; pass `env.DB` as-is.
- `jwtSecret` must be ≥ 32 bytes (`createAuth` throws `jwt_secret_weak`). Emails are trimmed + lowercased; passwords need ≥ 8 chars.
- `pbkdf2Iterations` defaults to 100,000 (Worker-safe; deliberately below OWASP 600k); changing it invalidates existing password hashes.
