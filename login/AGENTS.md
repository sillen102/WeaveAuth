# AGENTS.md (login)

Scoped to `login/` — overrides the repo-root `AGENTS.md` where they conflict.

## Deployer-replaceable page templates are JavaScript-free

`login/templates/*.html` (`login.html`, `register.html`, and any future page)
are rendered server-side (Tera, see `login/src/lib.rs`) and are meant to be
replaced wholesale by a deployer reskinning the login UI. A deployer supplies
**plain HTML and CSS only** — no `<script>` tags, no inline event handlers, no
client-side logic of any kind.

- Every dynamic value (`redirect_uri`, `next`/`own_url`, the form's `action`,
  OIDC links, error messages, the OIDC password-confirm view) is computed
  server-side in `render_page` and injected via Tera context — never via a
  client-side script reading `location.search`.
- Page-to-page navigation (login ↔ register) is wired via pre-rendered
  `hx-get`/`hx-target`/`hx-select`/`hx-push-url` attributes, not JS event
  listeners. htmx itself is loaded by the shell (`login/src/index.html`), not
  by these templates.
- The shell (`login/src/index.html`) is the one place in this crate allowed to
  have `<script>` — it's compiled into the binary, not deployer-replaceable,
  and exists specifically to own that routing/JS layer so the templates don't
  have to.
- When adding a field a template needs, add it to `PageQuery`/the Tera
  `Context` in `render_page` (or a new per-page render function) rather than
  reaching for client-side JS to fill it in.

Enforce this with a grep before adding anything to `login/templates/`:
`grep -rn '<script\|on[a-z]*="' login/templates/` should return nothing.
