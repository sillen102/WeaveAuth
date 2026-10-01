use std::error::Error;
use std::fmt::Write;

/// An error and every `source()` beneath it, joined with `": "`. Many
/// libraries (reqwest, hyper) keep the useful part -- "connection refused",
/// which field failed to parse -- in the source, so `Display` alone logs only
/// a generic kind. For logs only, never for a response body.
pub fn cause_chain(error: &(dyn Error + 'static)) -> String {
    let mut chain = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let _ = write!(chain, ": {cause}");
        source = cause.source();
    }
    chain
}

#[cfg(test)]
mod tests {
    use super::cause_chain;
    use std::fmt;

    #[derive(Debug)]
    struct Layer(&'static str, Option<Box<Layer>>);

    impl fmt::Display for Layer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for Layer {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.1.as_deref().map(|inner| inner as &(dyn std::error::Error + 'static))
        }
    }

    #[test]
    fn joins_every_source_outermost_first() {
        let error = Layer("error sending request", Some(Box::new(Layer("tcp connect error", Some(Box::new(Layer("connection refused", None)))))));

        assert_eq!(cause_chain(&error), "error sending request: tcp connect error: connection refused");
    }

    #[test]
    fn an_error_without_a_source_is_just_its_message() {
        assert_eq!(cause_chain(&Layer("alone", None)), "alone");
    }
}
