# mc-tunnel Fabric MOD

Drop this one jar into `mods/` and join `xxxx.minecraft` servers straight from
Minecraft's normal server list — no separate process, no config. The mod **bundles the
`mc-tunnel` daemon and starts it automatically** in the background (the daemon is the
analogue of the Tor process behind Tor Browser). The mod itself holds no keys and speaks
no libp2p; it just asks the local agent to resolve a name and rewrites the connection to
the `127.0.0.1:<port>` the agent serves it on.

If you already run `mc-tunnel agent` yourself, the mod detects and uses it instead.

## How it works

```
MC client ──"survival.k7f3….minecraft"──▶ ServerAddressMixin
                                              │  asks the local agent (127.0.0.1:42577)
                                              ▼
                                       mc-tunnel agent ──libp2p──▶ publisher's server
                                              │  replies {"listen":"127.0.0.1:53412"}
                                              ▼
       MC client connects to 127.0.0.1:53412 ── tunnel ── the real server
```

The mod hooks `ServerAddress.parse(String)`: when the host ends in `.minecraft` it calls
the agent and substitutes the returned local address. Everything else (the Minecraft
handshake, encryption, etc.) is untouched.

## Requirements

- Minecraft **1.21.1**, Fabric Loader ≥ 0.16, Java 21.
- That's it. The mod creates your identity and runs the daemon on first launch, under
  `<.minecraft>/config/mc-tunnel/`. (A bundled binary ships for Windows x86_64; other
  platforms fall back to using a `mc-tunnel agent` you start yourself — see logs.)

## Build

```sh
cd mod
./gradlew build
# jar lands in build/libs/mc-tunnel-mod-0.1.0.jar
```

Drop the jar into your `.minecraft/mods/` folder (with Fabric Loader installed).

## Config

The agent control port defaults to `42577`. Override it with either:

- JVM arg: `-Dmctunnel.agentPort=NNNNN`, or
- environment variable: `MCTUNNEL_AGENT_PORT=NNNNN`.

Set the same port with `mc-tunnel agent --control-port NNNNN`.

## Notes / limitations

- Resolving a name can take a few seconds (DHT lookup); the client briefly blocks while
  the agent works. If the agent isn't running, the join simply fails with a log line and
  Minecraft behaves as if the address were unreachable.
- This mod is client-only; servers need nothing.
