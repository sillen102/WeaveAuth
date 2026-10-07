//! Per-identifier login throttle: a growing delay between password attempts for one identifier,
//! whatever address they come from, so a spread-out guesser is slowed down too. It is a delay,
//! not a lockout (the identifier is never refused for good, so failing on purpose can't lock a
//! victim out), and it is keyed on the identifier alone, so a made-up one is treated exactly like
//! a real one and the response doesn't tell them apart. Memory is bounded: entries expire, and
//! only identifiers with failures are kept.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Attempts allowed back to back before the delay starts.
const FREE_ATTEMPTS: u32 = 5;
/// Attempts after the free ones that wait [`SHORT_DELAY`]; beyond them, [`LONG_DELAY`].
const SHORT_DELAY_ATTEMPTS: u32 = 5;
const SHORT_DELAY: Duration = Duration::from_secs(30);
const LONG_DELAY: Duration = Duration::from_secs(300);
/// An identifier nobody tried for this long starts from zero again.
const FORGET_AFTER: Duration = Duration::from_secs(3600);
/// Cap on tracked identifiers, so a flood of made-up ones can't grow the map without bound.
const MAX_TRACKED: usize = 100_000;

/// A hash of the normalized identifier. Never the identifier itself: nothing readable is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Key([u8; 32]);

impl Key {
    /// Case and surrounding whitespace don't make another identifier. Lowercasing is one char to
    /// one char, as Kratos' (Go) does: `to_lowercase` would split `İ` into two.
    pub(crate) fn of(identifier: &str) -> Self {
        let lowered: String = identifier
            .trim()
            .chars()
            .map(|c| c.to_lowercase().next().unwrap_or(c))
            .collect();
        let digest = Sha256::digest(lowered.as_bytes());
        Key(digest.into())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Admission {
    Admitted,
    /// Refused until then.
    Wait(Duration),
}

/// What Kratos' answer says about an admitted attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Wrong credentials: the attempt stays counted.
    Failed,
    /// The right ones: the identifier starts from zero.
    Succeeded,
    /// Kratos refused it before looking at the password (no CSRF cookie, say), so it says nothing
    /// about the account and is given back.
    NotAnAttempt,
}

struct Entry {
    /// Admitted attempts that haven't succeeded, in flight ones included, so parallel requests
    /// can't all slip through before the first answer is in.
    attempts: u32,
    last_attempt: Instant,
}

impl Entry {
    fn wait_until(&self) -> Instant {
        self.last_attempt + delay_after(self.attempts)
    }
}

fn delay_after(attempts: u32) -> Duration {
    if attempts < FREE_ATTEMPTS {
        Duration::ZERO
    } else if attempts < FREE_ATTEMPTS + SHORT_DELAY_ATTEMPTS {
        SHORT_DELAY
    } else {
        LONG_DELAY
    }
}

/// Frees a tenth of the map for new identifiers: first those not yet delaying anyone, oldest
/// first. A new identifier is always tracked, so a flood of made-up ones can't switch the throttle
/// off for the real one, and a batch keeps the scan off the hot path (expired entries are the
/// periodic [`sweep`](LoginThrottle::sweep)'s job).
fn evict(entries: &mut HashMap<Key, Entry>) {
    let mut ranked: Vec<_> = entries
        .iter()
        .map(|(key, entry)| ((entry.attempts >= FREE_ATTEMPTS, entry.last_attempt), *key))
        .collect();
    let batch = (MAX_TRACKED / 10).max(1).min(ranked.len());
    ranked.select_nth_unstable_by_key(batch - 1, |(rank, _)| *rank);
    for (_, key) in ranked.into_iter().take(batch) {
        entries.remove(&key);
    }
}

#[derive(Default)]
pub(crate) struct LoginThrottle {
    entries: Mutex<HashMap<Key, Entry>>,
}

impl LoginThrottle {
    /// Counts an attempt for `key` unless it has to wait. Pair every `Admitted` with a
    /// [`settle`](Self::settle).
    pub(crate) fn admit(&self, key: Key, now: Instant) -> Admission {
        let mut entries = self.lock();
        if let Some(entry) = entries.get_mut(&key)
            && now < entry.last_attempt + FORGET_AFTER
        {
            let wait_until = entry.wait_until();
            if now < wait_until {
                return Admission::Wait(wait_until - now);
            }
            entry.attempts += 1;
            entry.last_attempt = now;
            return Admission::Admitted;
        }
        if entries.len() >= MAX_TRACKED {
            evict(&mut entries);
        }
        entries.insert(
            key,
            Entry {
                attempts: 1,
                last_attempt: now,
            },
        );
        Admission::Admitted
    }

    pub(crate) fn settle(&self, key: Key, outcome: Outcome) {
        let mut entries = self.lock();
        match outcome {
            Outcome::Failed => {}
            Outcome::Succeeded => {
                entries.remove(&key);
            }
            Outcome::NotAnAttempt => {
                if let Some(entry) = entries.get_mut(&key) {
                    entry.attempts = entry.attempts.saturating_sub(1);
                    if entry.attempts == 0 {
                        entries.remove(&key);
                    }
                }
            }
        }
    }

    /// Drops identifiers nobody tried for [`FORGET_AFTER`].
    pub(crate) fn sweep(&self, now: Instant) {
        let mut entries = self.lock();
        entries.retain(|_, entry| now < entry.last_attempt + FORGET_AFTER);
        entries.shrink_to_fit();
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Key, Entry>> {
        // A panic while holding the lock can't leave the map half-updated in a way that matters.
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: &str) -> Key {
        Key::of(name)
    }

    #[test]
    fn spelling_variants_are_one_identifier() {
        assert_eq!(Key::of("A@B.c"), Key::of("  a@b.C "));
        assert_ne!(Key::of("a@b.c"), Key::of("a@b.d"));
    }

    #[test]
    fn lowercasing_is_one_to_one_like_gos() {
        assert_eq!(Key::of("vİctim@x"), Key::of("victim@x"));
    }

    #[test]
    fn the_free_attempts_wait_for_nothing() {
        let throttle = LoginThrottle::default();
        let now = Instant::now();

        for _ in 0..FREE_ATTEMPTS {
            assert_eq!(throttle.admit(key("a"), now), Admission::Admitted);
        }

        assert_eq!(throttle.admit(key("a"), now), Admission::Wait(SHORT_DELAY));
    }

    #[test]
    fn the_delay_counts_down_and_then_lets_one_attempt_through() {
        let throttle = LoginThrottle::default();
        let start = Instant::now();
        for _ in 0..FREE_ATTEMPTS {
            throttle.admit(key("a"), start);
        }

        let later = start + Duration::from_secs(10);
        assert_eq!(
            throttle.admit(key("a"), later),
            Admission::Wait(Duration::from_secs(20))
        );
        let ready = start + SHORT_DELAY;
        assert_eq!(throttle.admit(key("a"), ready), Admission::Admitted);
        // One attempt per delay, not a fresh burst.
        assert!(matches!(
            throttle.admit(key("a"), ready),
            Admission::Wait(_)
        ));
    }

    #[test]
    fn the_delay_grows_with_failures() {
        let throttle = LoginThrottle::default();
        let mut now = Instant::now();
        for _ in 0..FREE_ATTEMPTS {
            throttle.admit(key("a"), now);
        }
        for _ in 0..SHORT_DELAY_ATTEMPTS {
            now += SHORT_DELAY;
            assert_eq!(throttle.admit(key("a"), now), Admission::Admitted);
        }

        assert_eq!(throttle.admit(key("a"), now), Admission::Wait(LONG_DELAY));
    }

    #[test]
    fn identifiers_are_independent() {
        let throttle = LoginThrottle::default();
        let now = Instant::now();
        for _ in 0..FREE_ATTEMPTS {
            throttle.admit(key("a"), now);
        }

        assert_eq!(throttle.admit(key("b"), now), Admission::Admitted);
    }

    #[test]
    fn success_starts_over() {
        let throttle = LoginThrottle::default();
        let now = Instant::now();
        for _ in 0..FREE_ATTEMPTS {
            throttle.admit(key("a"), now);
        }
        throttle.settle(key("a"), Outcome::Succeeded);

        assert_eq!(throttle.len(), 0);
        for _ in 0..FREE_ATTEMPTS {
            assert_eq!(throttle.admit(key("a"), now), Admission::Admitted);
        }
    }

    #[test]
    fn an_attempt_that_says_nothing_about_the_password_is_given_back() {
        let throttle = LoginThrottle::default();
        let now = Instant::now();
        for _ in 0..FREE_ATTEMPTS {
            throttle.admit(key("a"), now);
            throttle.settle(key("a"), Outcome::NotAnAttempt);
        }

        assert_eq!(throttle.len(), 0);
        assert_eq!(throttle.admit(key("a"), now), Admission::Admitted);
    }

    #[test]
    fn a_failed_attempt_stays_counted() {
        let throttle = LoginThrottle::default();
        let now = Instant::now();
        for _ in 0..FREE_ATTEMPTS {
            throttle.admit(key("a"), now);
            throttle.settle(key("a"), Outcome::Failed);
        }

        assert!(matches!(throttle.admit(key("a"), now), Admission::Wait(_)));
    }

    #[test]
    fn an_identifier_nobody_tried_for_an_hour_is_forgotten() {
        let throttle = LoginThrottle::default();
        let now = Instant::now();
        for _ in 0..FREE_ATTEMPTS {
            throttle.admit(key("a"), now);
        }

        let later = now + FORGET_AFTER;
        assert_eq!(throttle.admit(key("a"), later), Admission::Admitted);
        for _ in 1..FREE_ATTEMPTS {
            assert_eq!(throttle.admit(key("a"), later), Admission::Admitted);
        }
    }

    #[test]
    fn the_sweep_drops_expired_identifiers_only() {
        let throttle = LoginThrottle::default();
        let now = Instant::now();
        throttle.admit(key("old"), now);
        throttle.admit(key("new"), now + FORGET_AFTER - Duration::from_secs(1));

        throttle.sweep(now + FORGET_AFTER);

        assert_eq!(throttle.len(), 1);
    }

    fn delayed(now: Instant) -> Entry {
        Entry {
            attempts: FREE_ATTEMPTS,
            last_attempt: now,
        }
    }

    #[test]
    fn a_full_map_evicts_the_undelayed_before_the_delayed() {
        let throttle = LoginThrottle::default();
        let now = Instant::now();
        for _ in 0..FREE_ATTEMPTS {
            throttle.admit(key("victim"), now);
        }
        {
            let mut entries = throttle.lock();
            for n in 0..MAX_TRACKED {
                entries.insert(
                    Key::of(&format!("filler-{n}")),
                    Entry {
                        attempts: 1,
                        last_attempt: now,
                    },
                );
            }
        }

        assert_eq!(throttle.admit(key("fresh"), now), Admission::Admitted);
        assert!(throttle.len() < MAX_TRACKED);
        assert!(matches!(
            throttle.admit(key("victim"), now),
            Admission::Wait(_)
        ));
    }

    #[test]
    fn a_new_identifier_is_still_throttled_when_the_map_is_full_of_delayed_ones() {
        let throttle = LoginThrottle::default();
        let now = Instant::now();
        {
            let mut entries = throttle.lock();
            for n in 0..MAX_TRACKED {
                entries.insert(Key::of(&format!("filler-{n}")), delayed(now));
            }
        }

        for _ in 0..FREE_ATTEMPTS {
            assert_eq!(throttle.admit(key("victim"), now), Admission::Admitted);
        }

        assert!(matches!(
            throttle.admit(key("victim"), now),
            Admission::Wait(_)
        ));
        assert!(throttle.len() <= MAX_TRACKED);
    }
}
