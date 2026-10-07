// Settings flow, password changed (after persistence). `session_id` is the session that changed it.
function(ctx) {
  identity_id: ctx.identity.id,
  session_id: ctx.session.id,
}
