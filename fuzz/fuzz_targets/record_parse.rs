#![no_main]
//! Fuzz the untrusted DHT-record parser. It must never panic, over-read, or OOM —
//! only return Ok/Err. If a verified record comes back, re-serializing it must round-trip.

use libfuzzer_sys::fuzz_target;
use mc_tunnel_core::record::Record;

fuzz_target!(|data: &[u8]| {
    if let Ok(rec) = Record::from_bytes(data) {
        // A parsed record must serialize back to something that re-parses identically.
        let bytes = rec.to_bytes();
        let again = Record::from_bytes(&bytes).expect("re-parse of our own bytes must succeed");
        assert_eq!(rec, again);
    }
});
