//! Random secrets (session cookies, remembered browsers, passkey request
//! ids) and how they are stored: only their SHA-256, so a copy of the
//! database can't be used to sign in, and there is no server key to leak.

use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::Error;

/// Length of a token as sent to the browser: 32 random bytes, base64url.
pub(crate) const TOKEN_CHARS: usize = 43;

/// A new random token and its stored hash.
pub(crate) fn new_token() -> Result<(Zeroizing<String>, [u8; 32]), Error> {
    let mut raw = Zeroizing::new([0u8; 32]);
    getrandom::fill(raw.as_mut()).map_err(|_| Error::Random)?;
    let text = Zeroizing::new(Base64UrlUnpadded::encode_string(raw.as_ref()));
    let hash = Sha256::digest(text.as_bytes()).into();
    Ok((text, hash))
}

/// The stored hash of a token the browser sent, or `None` when it isn't
/// shaped like one of ours (so junk never reaches the store).
pub(crate) fn hash_token(text: &str) -> Option<[u8; 32]> {
    if text.len() != TOKEN_CHARS || !text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return None;
    }
    // Reject non-canonical encodings (trailing bits set).
    let mut buf = [0u8; 32];
    Base64UrlUnpadded::decode(text, &mut buf).ok()?;
    Some(Sha256::digest(text.as_bytes()).into())
}

/// A random id, such as for a passkey request: 16 bytes, base64url.
#[cfg_attr(not(any(feature = "passkeys", feature = "test-util", test)), allow(dead_code))]
pub(crate) fn random_id() -> Result<String, Error> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).map_err(|_| Error::Random)?;
    Ok(Base64UrlUnpadded::encode_string(&raw))
}

/// A random version-4 UUID.
pub(crate) fn random_uuid() -> Result<uuid::Uuid, Error> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).map_err(|_| Error::Random)?;
    Ok(uuid::Builder::from_random_bytes(raw).into_uuid())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_round_trip_and_junk_is_refused() {
        let (t, h) = new_token().unwrap();
        assert_eq!(t.len(), TOKEN_CHARS);
        assert_eq!(hash_token(&t), Some(h));
        let (t2, h2) = new_token().unwrap();
        assert_ne!(*t, *t2);
        assert_ne!(h, h2);
        for bad in [
            "",
            "short",
            &"a".repeat(42),
            &"a".repeat(44),
            &format!("{}=", &t[..42]),
            &t.replace(|c: char| c.is_ascii_alphabetic(), "+"),
        ] {
            assert_eq!(hash_token(bad), None, "{bad}");
        }
        // 43 chars, but the last one has bits that don't fit 32 bytes.
        let noncanonical = format!("{}B", "A".repeat(42));
        assert_eq!(hash_token(&noncanonical), None);
    }

    #[test]
    fn ids_and_uuids_are_random() {
        assert_ne!(random_id().unwrap(), random_id().unwrap());
        let u = random_uuid().unwrap();
        assert_eq!(u.get_version_num(), 4);
        assert_ne!(u, random_uuid().unwrap());
    }
}
