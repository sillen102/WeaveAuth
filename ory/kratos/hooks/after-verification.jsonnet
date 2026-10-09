// After-verification web hook. Runs once an address is verified, so the identity's email is the
// verified one (the verification flow is only offered for it).
function(ctx) {
  identity_id: ctx.identity.id,
  email: ctx.identity.traits.email,
}
