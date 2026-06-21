# AGENTS.md — @treecombinator/sdk-auth

Auth (authentication) domain of the Tree Combinator SDK for Cloudflare Workers. D1 + Web Crypto (JWT/PBKDF2). The app injects a `sendEmail` function for the magic-link and password-reset mails. Run `AUTH_SCHEMA` once.

## Use

```ts
import { createAuth, AUTH_SCHEMA } from "@treecombinator/sdk-auth";

const auth = createAuth({
  db: env.DB,
  jwtSecret,
  appUrl: "https://app.example.com",
  sendEmail: (m) => myEmailAdapter.send(m), // the app wires its email here
});
const session = await auth.login(email, password);
```

`createAuth({ db, jwtSecret, appUrl, sendEmail, sessionTtlSec?, tokenTtlSec?, pbkdf2Iterations? })` →
`register`, `login`, `verifySession`, `startMagicLink`/`consumeMagicLink`,
`startPasswordReset`/`consumePasswordReset`. DDL: `AUTH_SCHEMA`.

## Notes

- This package OWNS the auth wire contract: `AuthUser`, `Session`, `AUTH_ROUTES`, `AuthRoute`, `SocialProvider`, `SocialLoginInput` — the client imports them from here.
- Email is an injected `sendEmail(message)` function (no port, no dependency on sdk-email).
- Errors are `TcError` (from `@treecombinator/sdk-common`) with specific codes: `email_already_registered`, `invalid_credentials`, `magic_link_invalid`, `reset_token_invalid`.
- `pbkdf2Iterations` defaults to 100,000 (Worker-safe); changing it invalidates existing password hashes.
