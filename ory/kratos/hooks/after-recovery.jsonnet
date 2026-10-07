// After-recovery web hook. Runs before the recovery session is persisted, and the context has no
// session: deleting every Kratos session of the identity here leaves only the new recovery session.
function(ctx) {
  identity_id: ctx.identity.id,
}
