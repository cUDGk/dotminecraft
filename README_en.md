# dotminecraft

*(Japanese: [README.md](README.md). The command-line tool is named `mc-tunnel`.)*

Expose and reach a Minecraft Java server at a **self-certifying** `xxxx.minecraft`
address — no central registry, no DNS, no port forwarding, no global IP. The design is
the same shape as a Tor onion service v3: the address *is* a commitment to a public key,
so a name cannot be impersonated and uniqueness needs no authority.

> **Status:** feature-complete for v1.0. All milestones M0–M6 plus OS-keyring storage,
> the `agent` control endpoint, and the Fabric MOD are implemented. `init`/`name`/
> `publish`/`connect`/`doctor`/`relay`/`agent`/`forget` all run. A TCP stream tunnels
> end-to-end between two separate identities by name alone — verified locally over the
> mDNS DHT, over a relay/bootstrap node with mDNS off, **and across two physically
> separate machines on different networks** (resolve via bootstrap, transit over the
> real network). Vanity grinding, rate limiting, fuzz targets, and CI (clippy/audit/deny)
> are in place; the Fabric MOD builds and its mixin resolves against MC 1.21.1.
>
> Not yet verified: DCUtR hole-punching between two hosts on *different real NATs with no
> overlay* (needs that specific multi-NAT setup). This is **not** Tor — see *Threat model*.

## Why this exists

A hobby server admin wants friends to join with just a short string, without renting a
VPS, opening router ports, or trusting a paid relay/DNS provider. mc-tunnel gives every
server an address derived from its own key. The first person to hold a key holds the
name; nobody else can take it or redirect it.

## How the name works

```
[vanity].[keyid].minecraft
survival.k7f3xq2m9bv8nt4a.minecraft
```

- `keyid = base32_nopad_lower(SHA-256(pubkey))[:16]` — 80 bits by default, dial up to
  260 with `--keyid-len` (max 52). Charset is Tor's `a-z2-7`: since the only digits are
  2-7, there's no `0`/`1` to confuse with the letters `o`/`l`.
- `vanity` is an optional 0–8 char label. By default it is just a signed label (mode A,
  free); `--vanity-prefix` will grind the keyid itself like an `.onion` vanity (mode B).
- To connect, the resolver looks up a **signed DHT record** that carries the full public
  key, verifies the signature, checks `SHA-256(pubkey)[:len] == keyid`, and rejects stale
  records. Only then does it open a tunnel. (SPEC §5.2)

## Architecture

Both sides run the **same binary**; only the mode differs. Each daemon is a bidirectional
proxy between a local TCP socket and an encrypted libp2p stream.

```
MC client <-TCP-> connect daemon <-libp2p(Noise)-> publish daemon <-TCP-> MC server
```

Networking rides on rust-libp2p: Kademlia DHT, Noise, yamux, Circuit Relay v2 + DCUtR +
AutoNAT for NAT traversal, over TCP and QUIC.

## Usage

On the **server** machine:

```sh
mc-tunnel init                              # generate identity, show keyid
mc-tunnel name                              # print your address (share this)
mc-tunnel publish --target 127.0.0.1:25565  # expose your MC server, runs until Ctrl-C
```

On a **friend's** machine:

```sh
mc-tunnel init                              # they need their own identity
mc-tunnel connect survival.k7f3....minecraft --listen 127.0.0.1:25566
```

Then add a Minecraft server pointing at `127.0.0.1:25566` and join. `mc-tunnel doctor`
prints listen addresses, NAT status, and peer count.

Running several identities on one host? Set `MC_TUNNEL_HOME` to a different directory per
instance (on Windows the default path comes from the Known Folder API, so `%APPDATA%`
won't relocate it — use `MC_TUNNEL_HOME`).

> On a LAN the two daemons find each other automatically via mDNS — no setup. Across the
> internet you need at least one `bootstrap` node in `config.toml` (`[network] bootstrap`);
> run one yourself with `mc-tunnel relay`. NAT hole-punching (M4) is still being hardened.

### Joining straight from Minecraft (Fabric MOD)

Instead of `connect`, run the agent and let the [Fabric MOD](mod/) rewrite addresses:

```sh
mc-tunnel agent                 # local control endpoint on 127.0.0.1:42577
```

With the mod installed (`mod/`, MC 1.21.1 + Fabric), just type `survival.k7f3….minecraft`
as a normal server address and join — the mod asks the agent to resolve it and tunnels to
localhost transparently. The mod holds no keys.

Remove an identity with `mc-tunnel forget` (clears the keyring entry and/or key file).

## Threat model (read this)

- **Anti-impersonation, yes.** Holding the name requires holding the private key. The
  keyid↔pubkey binding is checked on every resolve and is never skipped.
- **Anonymity, no.** Relay hops hide your location only *somewhat*. This does **not**
  provide Tor-grade anonymity and must not be relied on for it.
- **TCP / Java Edition only.** Bedrock (UDP) is out of scope.
- Untrusted input (DHT records, libp2p streams, MC TCP bytes) is length- and
  signature-checked before it is trusted. The whole workspace is `#![forbid(unsafe_code)]`.

See [SECURITY.md](SECURITY.md) for reporting and [SPEC.md](SPEC.md) for the full design.

## License

MIT — see [LICENSE](LICENSE).
