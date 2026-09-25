# Security Policy

## Reporting a vulnerability

Please report security issues privately, **not** as a public GitHub issue.

- Open a [GitHub private security advisory](https://github.com/cUDGk/dotminecraft/security/advisories/new), or
- email the maintainer (see the repository profile).

Include a description, reproduction steps, and impact. We aim to acknowledge within a few
days. Please give us a reasonable window to ship a fix before public disclosure.

## Scope

This project handles untrusted network input (DHT records, libp2p streams, raw Minecraft
TCP). Of particular interest:

- name/record forgery or impersonation (keyid ↔ pubkey binding bypass),
- replay of stale records to redirect connections,
- memory-safety or DoS in record parsing / protocol framing,
- the proxy being abused as a traffic-amplification relay,
- private-key exposure via logs, stdout, or the DHT.

## Hardening already in place

- `#![forbid(unsafe_code)]` across the whole workspace.
- Signed records with mandatory signature + keyid + freshness checks before trust.
- Size caps on deserialized records; the agent control channel caps bytes per connection.
- **Poisoning-resistant at two layers.** (1) Storage: every node validates an inbound
  record before storing it (Kademlia record filtering) — it must be validly signed *and*
  its pubkey must map to the storage key, so a third party cannot store or *overwrite* a
  record under a name that isn't theirs. (2) Resolution: a lookup may still return several
  records, so the resolver accepts the verified one with the **newest** timestamp and skips
  the rest. Forged records never verify; an attacker can at most add candidates we discard.
- **Replay-resistant.** Nodes store an inbound record only if it is strictly newer than the
  one they hold, and resolution picks the newest verified record, so a replayed older (but
  still validly signed) record can't suppress the owner's current location. Records carry a
  DHT expiry (`ts + ttl`) so stale locations age out.
- **Bounded proxies.** Both publish and connect proxies cap concurrent tunnels and rate-limit
  new connections; the agent control channel caps bytes per connection.
- Private keys stored owner-only (OS keyring, else 0600 file) and zeroized in memory;
  never logged or serialized to the network.
- Proxy listeners default to loopback; a non-loopback listen address logs a warning.
- `cargo audit` / `cargo deny` in CI; `cargo fuzz` targets for the record and name parsers
  plus always-on random-input robustness tests (SPEC §9.8–9.9).

## Known transitive advisories

Tracked (with removal triggers) in `deny.toml` / `.cargo/audit.toml`. It cannot be fixed by
us: the fix must come from libp2p's transitive dependencies.

| Advisory | What | Exposure in mc-tunnel |
|---|---|---|
| RUSTSEC-2024-0436 | `paste` unmaintained | Build-time proc-macro (Linux netlink path); no runtime impact. |

The earlier `hickory` DNS advisories (RUSTSEC-2026-0118 / 0119) are resolved since libp2p 0.57,
which moved to `hickory 0.26`.

## Accepted residual risks

- **Connecting dials addresses from a (signed) record.** When you resolve a name you chose
  to connect to, the daemon dials the multiaddrs in that name's *signed* record. A name
  owner could list internal/loopback/RFC1918 addresses, so your host may emit connection
  attempts to them (a limited SSRF/scan vector). libp2p still authenticates the peer at the
  Noise handshake, so no data flows to an unintended host — only connection attempts. We do
  **not** block private addresses by default because LAN operation (mDNS) legitimately needs
  them. Don't resolve names you don't intend to connect to; the `agent` resolves only on
  local request.
- **Minimum `keyid` is 16 chars (80 bits).** Shorter, weaker names are rejected.
