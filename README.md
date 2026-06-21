# @treecombinator/sdk-auth

---

> Developed by Danthur Lice.\
> Copyright © 2026 Tree Combinator.\
> Contact: dev (at) treecombinator.com

---

The **auth** domain of the Tree Combinator SDK — registration, login and session verification on Cloudflare D1 with Web Crypto (JWT/PBKDF2), plus magic-link and password-reset flows. It owns the auth wire contract the client consumes, and takes an injected `sendEmail` function for its mails — depending only on `@treecombinator/sdk-common` for the error type.

## Install

```bash
npm install github:treecombinator/sdk-auth
```

## Use

```ts
import { createAuth, AUTH_SCHEMA } from "@treecombinator/sdk-auth";

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
- `startMagicLink(email)` / `consumeMagicLink(token)` — passwordless login.
- `startPasswordReset(email)` / `consumePasswordReset(token, newPassword)` — reset flow.

Config: `{ db, jwtSecret, appUrl, sendEmail, sessionTtlSec?, tokenTtlSec?, pbkdf2Iterations? }`. The package also exports the wire contract (`AuthUser`, `Session`, `AUTH_ROUTES`, `SocialProvider`, `SocialLoginInput`) for the client, and the `AUTH_SCHEMA` DDL.

## Notes

- Errors are `TcError` with specific codes: `email_already_registered`, `invalid_credentials`, `magic_link_invalid`, `reset_token_invalid`.
- `sendEmail` is injected — the app wires its own email adapter; this package has no email dependency.
- `pbkdf2Iterations` defaults to 100,000 (a Worker-safe cost); changing it invalidates existing password hashes.
