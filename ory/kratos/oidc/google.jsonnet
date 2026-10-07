// Google: same mapping as generic.jsonnet. Google sends no phone number in the id_token
// (`phone_number` is optional in the schema); hooks reads it from the People API after sign-up
// (`profile_apis`). Google asserts `email_verified` in the id_token; the address is marked
// verified only when it is true. Add a claim to the traits here (and to identity.schema.json) to
// carry more of Google's profile into the identity, e.g.
//   [if 'picture' in claims then 'picture']: claims.picture,
local claims = {email_verified: false} + std.extVar('claims');

{
  identity: {
    traits: {
      [if 'email' in claims then 'email']: claims.email,
      [if 'given_name' in claims then 'first_name']: claims.given_name,
      [if 'family_name' in claims then 'last_name']: claims.family_name,
      [if 'phone_number' in claims then 'phone_number']: claims.phone_number,
    },
    verified_addresses: if 'email' in claims && claims.email_verified then [
      {via: 'email', value: claims.email},
    ] else [],
  },
}
