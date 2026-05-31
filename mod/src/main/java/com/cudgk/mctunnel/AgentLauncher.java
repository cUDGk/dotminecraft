package com.cudgk.mctunnel;

import net.fabricmc.loader.api.FabricLoader;

import java.io.InputStream;
import java.lang.ProcessBuilder.Redirect;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Makes the mod self-contained: it bundles the {@code mc-tunnel} daemon and starts it in
 * the background, so the player just drops in one jar — no separate process, no config (the
 * daemon is the analogue of the Tor process behind Tor Browser).
 *
 * Idempotent and retry-friendly: if a usable agent isn't up yet it tries to start one, and
 * a transient failure does not permanently disable later attempts (called again from
 * {@link AgentClient#resolve}). If a daemon is already running we use it; if no bundled
 * binary ships for this OS/arch we log how to run one manually and degrade gracefully.
 */
public final class AgentLauncher {
    private static Process process;

    private AgentLauncher() {}

    /** Ensure an agent is running. Safe to call repeatedly / from multiple threads. */
    public static synchronized void ensureRunning() {
        if (AgentClient.ping()) {
            return; // a usable agent (ours from a prior call, or the user's) is up
        }
        if (process != null && process.isAlive()) {
            return; // we launched one; it's still booting (control.json not written yet)
        }

        try {
            Path home = FabricLoader.getInstance().getConfigDir().resolve("mc-tunnel");
            Files.createDirectories(home);

            Path bin = extractBinary(home);
            if (bin == null) {
                McTunnelMod.LOGGER.warn(
                        "no bundled mc-tunnel binary for {}/{}; install mc-tunnel and run `mc-tunnel agent` to use .minecraft addresses",
                        osTag(), archTag());
                return;
            }
            if (!ensureIdentity(bin, home)) {
                McTunnelMod.LOGGER.warn("mc-tunnel identity setup failed; see {}", home.resolve("launcher.log"));
                return;
            }
            launchAgent(bin, home);
            if (waitReady()) {
                McTunnelMod.LOGGER.info("mc-tunnel agent started ({})", AgentClient.endpointDescription());
            } else {
                McTunnelMod.LOGGER.warn("mc-tunnel agent not ready yet; see {}", home.resolve("agent.log"));
            }
        } catch (Exception e) {
            McTunnelMod.LOGGER.warn("could not start the bundled mc-tunnel agent: {} "
                    + "(will retry; you can also run `mc-tunnel agent` manually)", e.toString());
        }
    }

    /**
     * Copy the bundled binary for this platform out of the jar to a version-stamped path,
     * via a temp file + atomic move. Version-stamped + skip-if-present avoids overwriting a
     * binary that may be running (and dodges AV/file locks). Returns the path or null.
     */
    private static Path extractBinary(Path home) throws Exception {
        String exe = osTag().equals("windows") ? ".exe" : "";
        Path dest = home.resolve("mc-tunnel-" + modVersion() + exe);
        if (Files.exists(dest)) {
            return dest; // already extracted this version
        }

        String resource = "/native/" + osTag() + "-" + archTag() + "/mc-tunnel" + exe;
        Path tmp = Files.createTempFile(home, "mc-tunnel-", ".tmp");
        try (InputStream in = AgentLauncher.class.getResourceAsStream(resource)) {
            if (in == null) {
                Files.deleteIfExists(tmp);
                return null; // no binary shipped for this platform
            }
            Files.copy(in, tmp, StandardCopyOption.REPLACE_EXISTING);
        }
        if (!osTag().equals("windows")) {
            Set<PosixFilePermission> perms = EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE);
            try {
                Files.setPosixFilePermissions(tmp, perms);
            } catch (UnsupportedOperationException ignored) {
                // non-POSIX FS
            }
        }
        try {
            Files.move(tmp, dest, StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception e) {
            // Another launch may have created it first; that's fine.
            Files.deleteIfExists(tmp);
            if (!Files.exists(dest)) {
                throw e;
            }
        }
        return dest;
    }

    /** Create an identity on first run; require a clean exit. Output is drained to a log. */
    private static boolean ensureIdentity(Path bin, Path home) throws Exception {
        if (base(bin, home, "name").start().waitFor() == 0) {
            return true; // identity already exists
        }
        McTunnelMod.LOGGER.info("creating mc-tunnel identity (first run)");
        return base(bin, home, "init").start().waitFor() == 0;
    }

    private static void launchAgent(Path bin, Path home) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(bin.toString(), "agent");
        pb.environment().put("MC_TUNNEL_HOME", home.toString());
        pb.directory(home.toFile());
        pb.redirectErrorStream(true);
        pb.redirectOutput(home.resolve("agent.log").toFile());
        process = pb.start();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> stop()));
    }

    private static void stop() {
        Process p = process;
        if (p == null || !p.isAlive()) {
            return;
        }
        p.destroy();
        try {
            if (!p.waitFor(2, TimeUnit.SECONDS)) {
                p.destroyForcibly();
            }
        } catch (InterruptedException e) {
            p.destroyForcibly();
            Thread.currentThread().interrupt();
        }
    }

    /** Poll until the agent answers (or we give up after ~10s). */
    private static boolean waitReady() throws InterruptedException {
        for (int i = 0; i < 20; i++) {
            if (AgentClient.ping()) {
                return true;
            }
            if (process != null && !process.isAlive()) {
                return false;
            }
            Thread.sleep(500);
        }
        return false;
    }

    /** ProcessBuilder for a short sub-command, draining output to launcher.log (no deadlock). */
    private static ProcessBuilder base(Path bin, Path home, String sub) {
        ProcessBuilder pb = new ProcessBuilder(bin.toString(), sub);
        pb.environment().put("MC_TUNNEL_HOME", home.toString());
        pb.directory(home.toFile());
        pb.redirectErrorStream(true);
        pb.redirectOutput(Redirect.appendTo(home.resolve("launcher.log").toFile()));
        return pb;
    }

    private static String modVersion() {
        return FabricLoader.getInstance().getModContainer("mc_tunnel")
                .map(c -> c.getMetadata().getVersion().getFriendlyString())
                .orElse("dev");
    }

    private static String osTag() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("win")) return "windows";
        if (os.contains("mac") || os.contains("darwin")) return "macos";
        return "linux";
    }

    private static String archTag() {
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        if (arch.equals("amd64") || arch.equals("x86_64")) return "x86_64";
        if (arch.equals("aarch64") || arch.equals("arm64")) return "aarch64";
        return arch;
    }
}
