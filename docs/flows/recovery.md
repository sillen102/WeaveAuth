# Account recovery

A recovery code proves control of the mailbox, not of the account's other sign-ins. So recovery
ends everything that could still be in someone else's hands, and the user must set a new password
before the account is usable with one again. Kratos runs the flow (`login` renders it); `hooks`
does the purge.

Relevant code:
- `login/src/pages.rs` -- `/recovery`, `/settings`
- `hooks/src/server/api/after_recovery.rs`, `after_password_change.rs`, `revocation.rs` -- the
  purge and the revocations
- `hooks/src/clients/{kratos,hydra,bff}.rs` -- the admin calls
- `bff/src/server/api/internal_revoke.rs` -- `POST /internal/revoke`
- `ory/kratos/kratos.yml` (`recovery`, `settings`), `ory/kratos/hooks/after-recovery.jsonnet`,
  `after-password-change.jsonnet`

```mermaid
sequenceDiagram
    autonumber
    actor U as Browser
    participant L as login
    participant K as Kratos
    participant M as Mail
    participant W as hooks
    participant H as Hydra
    participant F as bff

    U->>L: GET /recovery
    L-->>U: 303 /self-service/recovery/browser, then /recovery?flow=ID (email form)
    U->>L: POST email
    L->>K: forwarded
    K->>M: recovery code (6 digits, 60 minutes)
    K-->>U: the code form
    U->>L: POST code
    L->>K: forwarded
    Note over K: code accepted, before the recovery session exists
    K->>W: POST /kratos/after-recovery {identity_id}
    W->>K: replace the password with a random one, unlink every social login,<br/>delete passkey, webauthn, totp and lookup_secret credentials
    W->>K: delete every session of the identity, then purge again
    par concurrently
        W->>H: revoke consent sessions (all)
    and
        W->>H: revoke login sessions of the subject
    and
        W->>F: POST /internal/revoke {sub} (bff internal listener)
    end
    W-->>K: 200
    K-->>U: recovery session, 303 login /settings?flow=ID
    U->>L: POST new password
    L->>K: forwarded
    K->>W: POST /kratos/after-password-change {identity_id, session_id}
    W->>K: revoke every other Kratos session
    W->>H: revoke consent and login sessions
    W->>F: POST /internal/revoke {sub}
    W-->>K: 200
    K-->>U: 303 login /login
    U->>L: GET /login (no challenge)
    L-->>U: 303 bff /login?redirect_uri=WA_DEFAULT_REDIRECT_URI
    Note over U,K: Hydra sign-in as in login.md; Kratos asks for the new password
```

## Steps

**1. Ask for recovery.** `/recovery` starts a Kratos recovery flow (`use: code`): the user enters an
email address and Kratos mails a 6-digit code when an identity has that address. Kratos'
code limits (attempts, validity) apply.

**2. Code accepted: `POST /kratos/after-recovery`.** Kratos calls hooks after the code is accepted
and before the recovery session is created, so the context has no session and the hook can end
every session of the identity without ending the new one. Every step is attempted even if an
earlier one failed. Kratos' steps (1 to 3: purge, sessions, then the purge again, so a session
that was still alive cannot have added a credential in between) together get half of hooks'
request timeout. Then Hydra's consent sessions, Hydra's login sessions and bff (4 and 5) run
concurrently, each within 40% of the request timeout, so a Kratos or Hydra that hangs cannot leave
the rest alive:

1. The password credential gets a random password nobody knows. It is replaced instead of deleted
   because Kratos refuses to delete an account's last first-factor credential (a passkey-only
   account, say).
2. Every linked social login (Google and the like) is unlinked, each by its `provider:subject`
   identifier, after the password step so Kratos never sees the account lose its last first factor.
   The `webauthn`, `passkey`, `totp` and `lookup_secret` credentials are deleted. A type the
   identity does not have is not an error. A link stays out because whoever held the account before
   recovery may have added their own provider account to it, which would let them straight back
   in; the user links their provider again in settings.
3. Every Kratos session of the identity is revoked, then the credential purge of steps 1 and 2 runs
   once more.
4. Hydra's consent sessions (`all=true`, which also kills the refresh tokens) and login sessions of
   the subject are revoked. Revoking by subject does not trigger back-channel logout, so:
5. hooks calls bff's internal `POST /internal/revoke {sub}` (`WA_BFF_INTERNAL_URL`, authorized with
   `WA_BFF_INTERNAL_API_KEY`), which drops every bff session of that user and revokes their refresh
   tokens at Hydra. Their `wa_session` cookies stop working at once.

Any failed step makes the hook answer `502`; Kratos retries and then fails the flow, and every step
is safe to repeat. JWT access tokens already issued remain valid until they expire (15 minutes in
the shipped Hydra config), which is why they are short.

Accepting the code also marks the recovery address verified. That does not run the verification
hooks, so `verification_handler` is not told (tested).

**3. The settings flow.** Kratos gives the user the recovery session and sends them to `login`'s
`/settings`. The user must set a new password there. A user who leaves without one has an account
with no password, no passkeys and no social logins, so they recover again. The page shows only the
new-password form: `login` recognises the flow by its `request_url` (Kratos' recovery submission,
kept after a rejected password, unlike the recovery message) and leaves out the profile, social
and second-factor forms. Its recovery message (id `1060001`) is `login`'s own text (`templates/locales/en.json`, which a
deployer can reword or translate), because Kratos' wording offers social sign-in whether or not a provider
is configured.

**4. `POST /kratos/after-password-change`.** Any password change in the settings flow, recovery's
or not, calls this hook with the session that changed it. It revokes every *other* Kratos session
and the Hydra and bff sessions as in step 2 (parts 3 to 5), without touching credentials. The
bff revocation is by user, so the browser that changed the password is signed out of the
application too; the Kratos session it used stays, and Kratos then sends it to sign-in (step 5).

**5. Sign-in.** Kratos sends the browser to login's `/login`
(`settings.after.password.default_browser_return_url`), or to the flow's `return_to` when the
recovery carried one (Kratos copies it into the settings flow, and it wins). Without a challenge,
login hands it to bff's `/login` with `WA_DEFAULT_REDIRECT_URI` (an error page when that is
unset), and the Hydra sign-in runs as in [login.md](login.md). Hydra's login session is gone, so
Kratos does not accept the challenge on the session it kept: it asks for the password (its
"confirm it is you" form), and the user signs in with the new one and lands in the application.
