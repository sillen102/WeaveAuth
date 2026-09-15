/// Trims whitespace, case-folds an email, and strips a `+tag` suffix from the
/// local part (`alice+newsletter@example.com` -> `alice@example.com`), so the
/// same mailbox can't register or link as multiple distinct accounts.
///
/// Only `+` is treated as a tag separator. `-` is *not*: it's an ordinary
/// local-part character at most providers (`jane-doe@corp.com` is its own
/// mailbox, not a tag on `jane@corp.com`), and collapsing it would merge two
/// real people into one account -- which, via `resolve_oidc_login`, would let
/// one of them sign in straight into the other's account.
///
/// No crate does this -- `+` tagging isn't part of the email RFCs, it's a
/// convention some providers (Gmail, Outlook, ...) layer on top, so there's
/// no standard library to defer to.
pub(crate) fn normalize_email(email: &str) -> String {
    let email = email.trim().to_lowercase();
    match email.split_once('@') {
        Some((local, domain)) => {
            // A *leading* `+` isn't a tag separator -- stripping there would
            // leave an empty local part, collapsing every such address into a
            // single `@domain` account.
            let base = match local.split_once('+') {
                Some((base, _)) if !base.is_empty() => base,
                _ => local,
            };
            format!("{base}@{domain}")
        }
        None => email,
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_email;

    #[test]
    fn strips_plus_tag_from_local_part() {
        assert_eq!(normalize_email("alice+newsletter@example.com"), "alice@example.com");
    }

    #[test]
    fn keeps_hyphenated_local_parts_distinct() {
        assert_eq!(normalize_email("jane-doe@corp.com"), "jane-doe@corp.com");
        assert_ne!(normalize_email("jane-doe@corp.com"), normalize_email("jane@corp.com"));
    }

    #[test]
    fn does_not_empty_a_local_part_that_starts_with_a_plus() {
        assert_eq!(normalize_email("+weird@corp.com"), "+weird@corp.com");
        assert_ne!(normalize_email("+weird@corp.com"), normalize_email("+other@corp.com"));
    }

    #[test]
    fn lowercases_the_whole_address() {
        assert_eq!(normalize_email("Alice+Tag@Example.com"), "alice@example.com");
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(normalize_email("  alice@example.com  "), "alice@example.com");
    }

    #[test]
    fn leaves_addresses_without_a_tag_untouched() {
        assert_eq!(normalize_email("alice@example.com"), "alice@example.com");
    }

    #[test]
    fn only_strips_the_local_part_not_the_domain() {
        assert_eq!(normalize_email("bob@ex+ample.com"), "bob@ex+ample.com");
    }
}