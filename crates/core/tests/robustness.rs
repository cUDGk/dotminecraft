//! Parser robustness (SPEC §9.2/§9.9): the record parser and name parser must never
//! panic on hostile input — they may only return Ok or Err. This is the always-on,
//! cross-platform companion to the nightly `cargo fuzz` targets in `fuzz/`.

use mc_tunnel_core::name::Name;
use mc_tunnel_core::record::Record;

/// Tiny deterministic PRNG (xorshift64*) so the test is reproducible without a dep.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }
}

#[test]
fn record_parser_never_panics_on_random_bytes() {
    let mut rng = Rng(0x1234_5678_9abc_def0);
    for _ in 0..20_000 {
        let len = (rng.next() % 64) as usize; // mostly small; some near CBOR boundaries
        let mut buf = vec![0u8; len];
        for b in buf.iter_mut() {
            *b = rng.byte();
        }
        // Must not panic. The result itself is irrelevant.
        let _ = Record::from_bytes(&buf);
    }
}

#[test]
fn record_parser_rejects_oversize_without_allocating() {
    // Way over the cap: must be rejected up front, never parsed.
    let huge = vec![0xa1u8; 1 << 20];
    assert!(Record::from_bytes(&huge).is_err());
}

#[test]
fn name_parser_never_panics_on_random_ascii() {
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789.-_ABC";
    for _ in 0..20_000 {
        let len = (rng.next() % 40) as usize;
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            let idx = (rng.next() as usize) % alphabet.len();
            s.push(alphabet[idx] as char);
        }
        let _ = Name::parse(&s);
    }
}

#[test]
fn name_parser_handles_pathological_dots() {
    let many_dots = "a.".repeat(50);
    let cases = [
        "",
        ".",
        "..",
        "....minecraft",
        ".minecraft",
        "minecraft",
        &many_dots,
    ];
    for s in cases {
        let _ = Name::parse(s); // no panic
    }
}
