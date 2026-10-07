// After-registration web hook. Runs after the identity is persisted (no `response.parse`), so for
// OIDC the provider tokens can be read back through Kratos admin. The context holds neither
// tokens nor scopes; `provider` is taken from the path of the callback URL (flow.active is just
// "oidc", and absent for password and passkey). Only an OIDC flow has one, and the query string is
// not searched, so a crafted `?...callback/x` can't name a provider.
function(ctx)
  local callback = '/self-service/methods/oidc/callback/';
  local parts = std.split(std.split(ctx.request_url, '?')[0], callback);
  local oidc = 'active' in ctx.flow && ctx.flow.active == 'oidc';
  {
    identity_id: ctx.identity.id,
    email: ctx.identity.traits.email,
    email_verified: std.length([a for a in ctx.identity.verifiable_addresses if a.verified && a.value == ctx.identity.traits.email]) > 0,
    traits: ctx.identity.traits,
    flow_id: ctx.flow.id,
    method: if 'active' in ctx.flow then ctx.flow.active else null,
    provider: if oidc && std.length(parts) > 1 then std.split(parts[1], '/')[0] else null,
  }
