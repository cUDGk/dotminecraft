//! TCP <-> libp2p-stream proxying. SPEC §6.
//!
//! Both daemon modes are the same thing with the direction flipped: shovel bytes
//! between a local TCP socket and an encrypted libp2p stream until either side closes.
//! The Minecraft handshake is never inspected — raw bytes pass through (SPEC §6.3).

use anyhow::Result;
use mc_tunnel_net::{Control, NetHandle, PeerId, Stream, StreamProtocol, TUNNEL_PROTOCOL};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::FuturesAsyncReadCompatExt;

/// Token-bucket rate limiter for new inbound tunnels (SPEC §9.7) so the proxy can't be
/// driven to hammer the local MC server with connection churn. Burst == one second's
/// worth of tokens. Single-task use, so a plain `&mut self` is enough.
struct RateLimiter {
    tokens: f64,
    capacity: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl RateLimiter {
    fn new(per_sec: u32) -> Self {
        let cap = per_sec.max(1) as f64;
        Self {
            tokens: cap,
            capacity: cap,
            refill_per_sec: cap,
            last: Instant::now(),
        }
    }

    /// Try to spend one token. Returns false if the caller is over the rate right now.
    fn allow(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Pump bytes both ways between a tokio TCP stream and a libp2p stream until one closes.
/// `libp2p::Stream` is a *futures* AsyncRead/Write; `.compat()` adapts it to tokio so we
/// can use the well-tested `copy_bidirectional`.
async fn splice(tcp: TcpStream, libp2p_stream: Stream) -> Result<(u64, u64)> {
    tcp.set_nodelay(true).ok();
    let mut tcp = tcp;
    let mut p2p = libp2p_stream.compat();
    let (to_server, to_client) = tokio::io::copy_bidirectional(&mut tcp, &mut p2p).await?;
    Ok((to_server, to_client))
}

// ---------------------------------------------------------------------------
// publish side: inbound libp2p stream -> local MC server TCP
// ---------------------------------------------------------------------------

/// Accept inbound tunnel streams and forward each to the local MC server.
///
/// Two anti-amplification controls (SPEC §9.7): `max_conns` caps simultaneous tunnels,
/// and `new_conn_per_sec` caps how fast new tunnels may be opened.
pub async fn run_publish(
    mut control: Control,
    target: String,
    max_conns: usize,
    new_conn_per_sec: u32,
) -> Result<()> {
    use futures::StreamExt;

    let proto = StreamProtocol::try_from_owned(TUNNEL_PROTOCOL.to_string())
        .map_err(|e| anyhow::anyhow!("bad protocol string: {e}"))?;
    let mut incoming = control
        .accept(proto)
        .map_err(|e| anyhow::anyhow!("failed to register tunnel protocol: {e}"))?;

    let live = Arc::new(AtomicUsize::new(0));
    let mut rate = RateLimiter::new(new_conn_per_sec);
    tracing::info!(%target, max_conns, new_conn_per_sec, "publish proxy ready; waiting for inbound tunnels");

    while let Some((peer, stream)) = incoming.next().await {
        if !rate.allow() {
            tracing::warn!(%peer, new_conn_per_sec, "new-connection rate exceeded; dropping inbound stream");
            continue;
        }
        let n = live.load(Ordering::Relaxed);
        if n >= max_conns {
            tracing::warn!(%peer, n, max_conns, "connection cap reached; dropping inbound stream");
            // Dropping `stream` closes it.
            continue;
        }
        let target = target.clone();
        let live = live.clone();
        live.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            match TcpStream::connect(&target).await {
                Ok(tcp) => {
                    tracing::debug!(%peer, "tunnel up");
                    if let Err(e) = splice(tcp, stream).await {
                        tracing::debug!(%peer, error = %e, "tunnel closed with error");
                    }
                }
                Err(e) => {
                    tracing::warn!(%peer, %target, error = %e, "cannot reach local MC server")
                }
            }
            live.fetch_sub(1, Ordering::Relaxed);
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// connect side: inbound local TCP -> outbound libp2p stream to publisher
// ---------------------------------------------------------------------------

/// Sensible caps for the local listener. Loopback by default, but if the user exposes it
/// these stop the connect proxy from being an unbounded resource sink (SPEC §9.7).
pub const CONNECT_MAX_CONNS: usize = 128;
pub const CONNECT_MAX_CONN_RATE: u32 = 64;

/// For each local TCP connection on `listener`, open a fresh tunnel stream to `peer` and
/// splice them. One TCP connection == one stream (SPEC §6.3). The caller binds the
/// listener so it can choose a fixed port (`connect`) or an ephemeral one (`agent`).
/// Bounded by a concurrent-connection cap and a new-connection rate limit.
pub async fn run_connect(
    _handle: NetHandle,
    control: Control,
    listener: TcpListener,
    peer: PeerId,
) -> Result<()> {
    let proto = StreamProtocol::try_from_owned(TUNNEL_PROTOCOL.to_string())
        .map_err(|e| anyhow::anyhow!("bad protocol string: {e}"))?;
    let live = Arc::new(AtomicUsize::new(0));
    let mut rate = RateLimiter::new(CONNECT_MAX_CONN_RATE);
    tracing::info!(%peer, "connect proxy listening; point your MC client here");

    loop {
        let (tcp, from) = listener.accept().await?;
        if !rate.allow() {
            tracing::warn!(%from, "new-connection rate exceeded; dropping local connection");
            continue;
        }
        if live.load(Ordering::Relaxed) >= CONNECT_MAX_CONNS {
            tracing::warn!(%from, cap = CONNECT_MAX_CONNS, "connection cap reached; dropping");
            continue;
        }
        let mut control = control.clone();
        let proto = proto.clone();
        let live = live.clone();
        live.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            match control.open_stream(peer, proto).await {
                Ok(stream) => {
                    tracing::debug!(%from, "tunnel up");
                    if let Err(e) = splice(tcp, stream).await {
                        tracing::debug!(%from, error = %e, "tunnel closed with error");
                    }
                }
                Err(e) => tracing::warn!(%from, error = %e, "failed to open tunnel to publisher"),
            }
            live.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::RateLimiter;
    use std::time::Duration;

    #[test]
    fn rate_limiter_allows_a_burst_then_throttles_and_refills() {
        // capacity == per_sec == 4: a 4-token burst is allowed, the 5th is denied.
        let mut rl = RateLimiter::new(4);
        for _ in 0..4 {
            assert!(rl.allow(), "burst tokens should be allowed");
        }
        assert!(!rl.allow(), "over-burst should be denied");

        // After ~0.3s at 4 tokens/s, ~1 token has refilled.
        std::thread::sleep(Duration::from_millis(300));
        assert!(rl.allow(), "a token should have refilled");
        assert!(!rl.allow(), "but only ~one, so the next is denied");
    }

    #[test]
    fn rate_limiter_never_zero_division_or_panic_on_minimal_rate() {
        // per_sec 0 is clamped to 1; must not panic and must allow exactly one.
        let mut rl = RateLimiter::new(0);
        assert!(rl.allow());
        assert!(!rl.allow());
    }
}
