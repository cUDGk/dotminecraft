//! Security-critical acceptance tests (SPEC §13): a tampered, mis-signed, mis-keyed,
//! or stale record MUST be rejected. These mirror the four checks in SPEC §5.2.

use mc_tunnel_core::error::VerifyError;
use mc_tunnel_core::name::keyid_from_pubkey;
use mc_tunnel_core::record::{Record, RecordBody};
use mc_tunnel_core::{Identity, DEFAULT_KEYID_LEN, RECORD_VERSION};

const NOW: u64 = 1_900_000_000;
const SKEW: u64 = 300;

fn make_record(id: &Identity, ts: u64) -> (Record, String) {
    let pk = id.public_bytes();
    let keyid = keyid_from_pubkey(&pk, DEFAULT_KEYID_LEN);
    let body = RecordBody {
        v: RECORD_VERSION,
        pubkey: pk,
        peer_id: "12D3KooWFakePeerId".to_string(),
        addrs: vec!["/ip4/127.0.0.1/tcp/4001".to_string()],
        vanity: "survival".to_string(),
        ts,
        ttl: 600,
    };
    (Record::sign(body, id.signing_key()), keyid)
}

#[test]
fn valid_record_verifies() {
    let id = Identity::generate();
    let (rec, keyid) = make_record(&id, NOW);
    assert_eq!(rec.verify(&keyid, NOW, SKEW), Ok(()));
}

#[test]
fn roundtrips_through_bytes() {
    let id = Identity::generate();
    let (rec, keyid) = make_record(&id, NOW);
    let bytes = rec.to_bytes();
    let parsed = Record::from_bytes(&bytes).expect("should parse");
    assert_eq!(parsed, rec);
    assert_eq!(parsed.verify(&keyid, NOW, SKEW), Ok(()));
}

#[test]
fn tampered_body_is_rejected() {
    let id = Identity::generate();
    let (mut rec, keyid) = make_record(&id, NOW);
    // Attacker rewrites the reachable address but can't re-sign.
    rec.body.addrs = vec!["/ip4/6.6.6.6/tcp/4001".to_string()];
    assert_eq!(
        rec.verify(&keyid, NOW, SKEW),
        Err(VerifyError::BadSignature)
    );
}

#[test]
fn bad_signature_is_rejected() {
    let id = Identity::generate();
    let (mut rec, keyid) = make_record(&id, NOW);
    rec.sig[0] ^= 0xff;
    assert_eq!(
        rec.verify(&keyid, NOW, SKEW),
        Err(VerifyError::BadSignature)
    );
}

#[test]
fn keyid_mismatch_is_rejected() {
    // A record validly signed by an *attacker's* key cannot satisfy a victim's keyid.
    let attacker = Identity::generate();
    let victim = Identity::generate();
    let (rec, _) = make_record(&attacker, NOW);
    let victim_keyid = keyid_from_pubkey(&victim.public_bytes(), DEFAULT_KEYID_LEN);
    assert_eq!(
        rec.verify(&victim_keyid, NOW, SKEW),
        Err(VerifyError::KeyidMismatch)
    );
}

#[test]
fn swapped_pubkey_breaks_signature_first() {
    // If an attacker drops in the victim's pubkey to pass the keyid check, the
    // signature (made with the attacker's key) no longer verifies.
    let attacker = Identity::generate();
    let victim = Identity::generate();
    let (mut rec, _) = make_record(&attacker, NOW);
    rec.body.pubkey = victim.public_bytes();
    let victim_keyid = keyid_from_pubkey(&victim.public_bytes(), DEFAULT_KEYID_LEN);
    assert_eq!(
        rec.verify(&victim_keyid, NOW, SKEW),
        Err(VerifyError::BadSignature)
    );
}

#[test]
fn stale_timestamp_is_rejected() {
    let id = Identity::generate();
    let (rec, keyid) = make_record(&id, NOW - SKEW - 1);
    assert!(matches!(
        rec.verify(&keyid, NOW, SKEW),
        Err(VerifyError::StaleTimestamp { .. })
    ));
}

#[test]
fn future_timestamp_is_rejected() {
    let id = Identity::generate();
    let (rec, keyid) = make_record(&id, NOW + SKEW + 1);
    assert!(matches!(
        rec.verify(&keyid, NOW, SKEW),
        Err(VerifyError::StaleTimestamp { .. })
    ));
}

#[test]
fn oversized_record_is_rejected_before_parse() {
    let big = vec![0u8; 9 * 1024];
    assert_eq!(
        Record::from_bytes(&big),
        Err(VerifyError::TooLarge(8 * 1024))
    );
}

#[test]
fn select_verified_picks_the_valid_record_among_junk() {
    use mc_tunnel_core::record::select_verified;
    let id = Identity::generate();
    let (rec, keyid) = make_record(&id, NOW);

    // A DHT lookup returns: random junk, a wrong-key (attacker) record, then the real one.
    let attacker = Identity::generate();
    let (att_rec, _) = make_record(&attacker, NOW);
    let candidates = vec![
        vec![0xde, 0xad, 0xbe, 0xef], // unparseable junk
        att_rec.to_bytes(),           // validly signed but wrong keyid (poison)
        rec.to_bytes(),               // the genuine record
    ];

    let chosen = select_verified(&candidates, &keyid, NOW, SKEW).expect("should find the real one");
    assert_eq!(chosen, rec);
}

#[test]
fn storage_check_accepts_genuine_rejects_poison() {
    use mc_tunnel_core::record::{authorizes_storage_key, dht_key};

    let owner = Identity::generate();
    let (rec, keyid) = make_record(&owner, NOW);
    let owner_key = dht_key(&keyid);

    // The owner's record may be stored under the owner's key.
    assert!(authorizes_storage_key(&rec, &owner_key));

    // An attacker may NOT store their (validly signed) record under the owner's key —
    // their pubkey doesn't hash to it. This is what stops overwrite-poisoning.
    let attacker = Identity::generate();
    let (att_rec, _) = make_record(&attacker, NOW);
    assert!(!authorizes_storage_key(&att_rec, &owner_key));

    // A tampered record (broken signature) is refused even under its own key.
    let mut tampered = rec.clone();
    tampered.sig[0] ^= 0xff;
    assert!(!authorizes_storage_key(&tampered, &owner_key));
}

#[test]
fn select_verified_prefers_the_newest_record() {
    use mc_tunnel_core::record::select_verified;
    let id = Identity::generate();
    // Same owner, an older and a newer record (both validly signed, both in-skew). A
    // replayed older record must not win over the current one.
    let (old, keyid) = make_record(&id, NOW - 100);
    let (new, _) = make_record(&id, NOW);
    let candidates = vec![new.to_bytes(), old.to_bytes()]; // newest listed first...
    let chosen = select_verified(&candidates, &keyid, NOW, SKEW).unwrap();
    assert_eq!(chosen.body.ts, NOW);
    // ...and also when the older one is listed first.
    let candidates = vec![old.to_bytes(), new.to_bytes()];
    assert_eq!(
        select_verified(&candidates, &keyid, NOW, SKEW)
            .unwrap()
            .body
            .ts,
        NOW
    );
}

#[test]
fn select_verified_returns_none_when_all_poisoned() {
    use mc_tunnel_core::record::select_verified;
    let victim = Identity::generate();
    let victim_keyid = keyid_from_pubkey(&victim.public_bytes(), DEFAULT_KEYID_LEN);

    // Only junk and an attacker's record under the victim's key — nothing should verify.
    let attacker = Identity::generate();
    let (att_rec, _) = make_record(&attacker, NOW);
    let candidates = vec![vec![1, 2, 3], att_rec.to_bytes()];

    assert!(select_verified(&candidates, &victim_keyid, NOW, SKEW).is_none());
}
