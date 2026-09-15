/// Trims whitespace, case-folds an email, and strips a `+tag` or `-tag`
/// suffix from the local part (`alice+newsletter@example.com` and
/// `alice-newsletter@example.com` both -> `alice@example.com`), so the same
/// mailbox can't register or link as multiple distinct accounts.
///
/// No crate does this -- neither tagging convention is part of the email
/// RFCs, they're layered on top by specific providers (`+`: Gmail, Outlook;
/// `-`: Yahoo, Fastmail), so there's no standard library to defer to.
pub(crate) fn normalize_email(email: &str) -> String {
    let email = email.trim().to_lowercase();
    match email.split_once('@') {
        Some((local, domain)) => {
            let tag_start = local.find(['+', '-']).unwrap_or(local.len());
            format!("{}@{domain}", &local[..tag_start])
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
    fn strips_dash_tag_from_local_part() {
        assert_eq!(normalize_email("alice-newsletter@example.com"), "alice@example.com");
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
        assert_eq!(normalize_email("bob@ex-ample.com"), "bob@ex-ample.com");
    }
}