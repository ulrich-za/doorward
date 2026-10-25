//! Usernames: one account per name however it is capitalised, and no two
//! names that look alike.
//!
//! A username is normalised (Unicode NFKC) and checked: 1–64 characters, only
//! letters and digits plus `. _ - @ +`, from one writing system (Latin mixed
//! with Han, Hiragana, Katakana or Hangul is allowed, as Unicode's "highly
//! restrictive" profile does). Its *key* is the normalised name in lowercase,
//! used to find the account at sign-in, so "Admin" and "admin" are one account.
//! Its *skeleton* (Unicode UTS #39) maps look-alike characters to one form, so
//! "paypal" and "pаypal" (with a Cyrillic "а") can't both be registered.

use unicode_normalization::UnicodeNormalization;
use unicode_security::{RestrictionLevel, RestrictionLevelDetection};

use crate::error::Error;

/// Longest username, in characters.
pub const MAX_USERNAME_CHARS: usize = 64;
/// Input longer than this many bytes is never looked up or normalised.
const MAX_INPUT_BYTES: usize = 1024;
const PUNCTUATION: &[char] = &['.', '_', '-', '@', '+'];

/// A checked username.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Username {
    display: String,
    key: String,
    skeleton: String,
}

impl Username {
    /// Check and normalise a username for a new account or a rename.
    pub fn parse(input: &str) -> Result<Username, Error> {
        if input.len() > MAX_INPUT_BYTES {
            return Err(Error::UsernameInvalid);
        }
        let display: String = input.trim().nfkc().collect();
        let chars = display.chars().count();
        if chars == 0 || chars > MAX_USERNAME_CHARS {
            return Err(Error::UsernameInvalid);
        }
        if !display.chars().all(|c| c.is_alphanumeric() || PUNCTUATION.contains(&c)) {
            return Err(Error::UsernameInvalid);
        }
        // The ASCII punctuation is common to every script; judge the rest.
        let letters: String = display.chars().filter(|c| !PUNCTUATION.contains(c)).collect();
        if letters.is_empty() || !letters.as_str().check_restriction_level(RestrictionLevel::HighlyRestrictive) {
            return Err(Error::UsernameInvalid);
        }
        let key = key_of(&display);
        let skeleton = skeleton_of(&key);
        Ok(Username { display, key, skeleton })
    }

    /// The name as the user wrote it (normalised).
    pub fn as_str(&self) -> &str {
        &self.display
    }

    /// The lookup key: lowercase, normalised.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The look-alike skeleton, unique among accounts.
    pub fn skeleton(&self) -> &str {
        &self.skeleton
    }
}

impl std::fmt::Display for Username {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.display)
    }
}

/// The lookup key for what someone typed at sign-in, without the checks a
/// new name gets (a name that fails them can't exist, so it simply won't be
/// found). `None` for input too long to be a username.
pub(crate) fn lookup_key(input: &str) -> Option<String> {
    if input.len() > MAX_INPUT_BYTES {
        return None;
    }
    let display: String = input.trim().nfkc().collect();
    if display.is_empty() || display.chars().count() > MAX_USERNAME_CHARS {
        return None;
    }
    Some(key_of(&display))
}

fn key_of(display: &str) -> String {
    display.to_lowercase().nfkc().collect()
}

fn skeleton_of(key: &str) -> String {
    let s: String = unicode_security::skeleton(key).collect();
    s.to_lowercase().nfkc().collect()
}

/// Longest role name.
pub const MAX_ROLE_CHARS: usize = 64;

/// Check a role name: 1–64 of `a-z 0-9 _ - . :`.
pub(crate) fn check_role(role: &str) -> Result<(), Error> {
    let ok = !role.is_empty()
        && role.len() <= MAX_ROLE_CHARS
        && role.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-.:".contains(&b));
    if ok { Ok(()) } else { Err(Error::RoleInvalid) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_names_and_emails_are_allowed() {
        for n in [
            "admin",
            "Ulrich",
            "ulrich.h",
            "me@example.com",
            "first+tag@x.co",
            "o'brien".replace('\'', "-").as_str(),
            "Zoë",
            "李小龍",
            "ひらがな",
            "user_1",
        ] {
            assert!(Username::parse(n).is_ok(), "{n}");
        }
    }

    #[test]
    fn case_is_one_account() {
        let a = Username::parse("Admin").unwrap();
        let b = Username::parse("admin").unwrap();
        assert_eq!(a.key(), b.key());
        assert_eq!(a.as_str(), "Admin");
        assert_eq!(lookup_key("  ADMIN ").as_deref(), Some("admin"));
    }

    #[test]
    fn normalisation_unifies_compatibility_forms() {
        // Full-width letters and a precomposed/decomposed accent.
        let a = Username::parse("ＡＤＭＩＮ").unwrap();
        assert_eq!(a.key(), "admin");
        let b = Username::parse("Zoe\u{308}").unwrap();
        let c = Username::parse("Zo\u{eb}").unwrap();
        assert_eq!(b.key(), c.key());
    }

    #[test]
    fn look_alikes_share_a_skeleton() {
        // Mixed Latin and Cyrillic is refused outright…
        assert!(Username::parse("p\u{430}ypal").is_err());
        // …and an all-Cyrillic look-alike ("рарау") is allowed as a name but
        // collides with the Latin "papay".
        let latin = Username::parse("papay").unwrap();
        let cyr = Username::parse("\u{440}\u{430}\u{440}\u{430}\u{443}").unwrap();
        assert_eq!(latin.skeleton(), cyr.skeleton());
        assert_ne!(latin.key(), cyr.key());
        // Digits that look like letters.
        assert_eq!(Username::parse("pau1").unwrap().skeleton(), Username::parse("paul").unwrap().skeleton());
        assert_eq!(Username::parse("b0b").unwrap().skeleton(), Username::parse("bob").unwrap().skeleton());
    }

    #[test]
    fn bad_names_are_refused() {
        for n in [
            "",
            "   ",
            "a b",
            "a\u{0}b",
            "admin\u{200b}",
            "tab\tname",
            "semi;colon",
            "slash/name",
            "<script>",
            "...",
            "\u{202e}nimda",
            &"a".repeat(65),
            &"x".repeat(5000),
        ] {
            assert!(Username::parse(n).is_err(), "{n:?}");
        }
        assert!(Username::parse(&"a".repeat(64)).is_ok());
        assert_eq!(lookup_key(&"x".repeat(5000)), None);
        assert_eq!(lookup_key(""), None);
    }

    #[test]
    fn roles() {
        for r in ["admin", "tech", "sales:manager", "customer-contact", "a.b_c"] {
            assert!(check_role(r).is_ok(), "{r}");
        }
        for r in ["", "Admin", "has space", "ünicode", &"r".repeat(65), "semi;"] {
            assert!(check_role(r).is_err(), "{r}");
        }
    }
}
