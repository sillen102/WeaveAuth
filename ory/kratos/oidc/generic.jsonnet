// Mapper for any OpenID Connect provider (the system-tests fake IdP included): copies the
// id_token's `email`, `given_name`, `family_name` and `phone_number` into the identity traits.
// The schema requires `email`, `first_name` and `last_name`, and Kratos asks the user for any the
// provider leaves out; `phone_number` is optional. The address is marked verified only when the
// provider asserts `email_verified: true`.
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
