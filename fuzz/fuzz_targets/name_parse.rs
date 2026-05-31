#![no_main]
//! Fuzz the self-certifying name parser. Any UTF-8 string must parse to Ok/Err without
//! panicking, and a successfully parsed name must round-trip through Display.

use libfuzzer_sys::fuzz_target;
use mc_tunnel_core::name::Name;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(name) = Name::parse(s) {
            // Re-parsing the canonical form must yield the same name.
            let reparsed = Name::parse(&name.to_string()).expect("display form must re-parse");
            assert_eq!(name, reparsed);
        }
    }
});
