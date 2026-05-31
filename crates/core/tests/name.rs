//! Name derivation / parsing round-trips and charset rejection (SPEC §4).

use mc_tunnel_core::error::CoreError;
use mc_tunnel_core::name::{keyid_full_from_pubkey, Name};
use mc_tunnel_core::{Identity, DEFAULT_KEYID_LEN, MAX_KEYID_LEN};

#[test]
fn derive_and_parse_roundtrip() {
    let id = Identity::generate();
    let name = id.name("survival", DEFAULT_KEYID_LEN).unwrap();
    let text = name.to_string();
    assert!(text.ends_with(".minecraft"));
    let parsed = Name::parse(&text).unwrap();
    assert_eq!(parsed, name);
    assert_eq!(parsed.keyid_len(), DEFAULT_KEYID_LEN);
}

#[test]
fn no_vanity_roundtrip() {
    let id = Identity::generate();
    let name = id.name("", DEFAULT_KEYID_LEN).unwrap();
    let text = name.to_string();
    // exactly keyid.minecraft
    assert_eq!(text.matches('.').count(), 1);
    assert_eq!(Name::parse(&text).unwrap(), name);
}

#[test]
fn keyid_is_base32_lower_and_right_length() {
    let id = Identity::generate();
    let full = keyid_full_from_pubkey(&id.public_bytes());
    assert_eq!(full.len(), 52); // 256 bits / 5 bits per char, no padding
    assert!(full.chars().all(|c| matches!(c, 'a'..='z' | '2'..='7')));
}

#[test]
fn longer_keyid_commits_more_bits() {
    let id = Identity::generate();
    let n16 = id.name("", 16).unwrap();
    let n26 = id.name("", 26).unwrap();
    assert!(n26.keyid.starts_with(&n16.keyid));
    assert_eq!(n26.keyid_len(), 26);
}

#[test]
fn longest_possible_name_fits_minecraft_field() {
    // Minecraft's Add Server / Direct Connect address field caps at 128 chars (verified in
    // the 1.21.1 client). Our worst case — 8-char vanity + max keyid + ".minecraft" — must
    // stay under it so the longest valid name is still typeable without a mod tweak.
    let id = Identity::generate();
    let name = id.name("survivor", MAX_KEYID_LEN).unwrap(); // 8 + 1 + 52 + 10 = 71
    assert!(
        name.to_string().len() <= 128,
        "name length {} exceeds MC's 128-char field",
        name.to_string().len()
    );
}

#[test]
fn rejects_keyid_shorter_than_minimum() {
    // 80-bit floor: a 15-char keyid must be refused at derivation and at parse.
    let id = Identity::generate();
    assert!(id.name("", 15).is_err());
    assert!(matches!(
        Name::parse("abcdefgh2345672.minecraft"), // 15 base32 chars
        Err(CoreError::KeyidLen { .. })
    ));
    // 16 is accepted.
    assert!(id.name("", 16).is_ok());
}

#[test]
fn rejects_wrong_suffix() {
    assert_eq!(
        Name::parse("abcdefgh23456789.craft"),
        Err(CoreError::BadSuffix("minecraft"))
    );
}

#[test]
fn rejects_bad_charset() {
    // '0' '1' '8' '9' are not in the charset.
    assert_eq!(
        Name::parse("abcdef0189234567.minecraft"),
        Err(CoreError::KeyidCharset)
    );
}

#[test]
fn rejects_too_many_labels() {
    assert_eq!(
        Name::parse("a.b.abcdefgh23456789.minecraft"),
        Err(CoreError::TooManyLabels)
    );
}

#[test]
fn rejects_overlong_vanity() {
    assert!(matches!(
        Name::parse("toolongvanity.abcdefgh23456789.minecraft"),
        Err(CoreError::VanityTooLong(_))
    ));
}

#[test]
fn parse_is_case_insensitive() {
    let id = Identity::generate();
    let name = id.name("survival", DEFAULT_KEYID_LEN).unwrap();
    let upper = name.to_string().to_uppercase();
    assert_eq!(Name::parse(&upper).unwrap(), name);
}
