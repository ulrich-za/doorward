//! The most common passwords, for refusing them as new passwords.
//!
//! `common-passwords.txt` holds the 5,000 most common passwords of 8 or
//! more printable ASCII characters, lowercased, in order of frequency. It is
//! taken from SecLists' `xato-net-10-million-passwords-100000.txt`
//! (MIT licence, Copyright (c) 2018 Daniel Miessler; see NOTICE).

use std::collections::HashSet;
use std::sync::OnceLock;

const LIST: &str = include_str!("common-passwords.txt");

fn set() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| LIST.lines().map(str::trim).filter(|l| !l.is_empty()).collect())
}

/// Is this (lowercased) password among the most common?
pub(crate) fn is_common(lower: &str) -> bool {
    set().contains(lower)
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_list_is_loaded() {
        assert_eq!(super::set().len(), 5000);
        for p in ["password", "12345678", "baseball", "trustno1", "iloveyou"] {
            assert!(super::is_common(p), "{p}");
        }
        assert!(!super::is_common("correct horse battery staple"));
    }
}
