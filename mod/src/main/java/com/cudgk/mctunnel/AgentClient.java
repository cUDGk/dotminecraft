package com.cudgk.mctunnel;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import net.fabricmc.loader.api.FabricLoader;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Client for the local {@code mc-tunnel agent} control endpoint (SPEC §11).
 *
 * The agent listens on a random loopback port and writes that port plus a random token to
 * an owner-only {@code control.json}; we read it to learn where to connect and to
 * authenticate (so another local process can't squat a fixed port or drive tunnels). All
 * traffic stays on 127.0.0.1; no keys or libp2p here. The returned address is validated to
 * be loopback before it's ever used, so a misbehaving agent can't redirect us off-box.
 */
public final class AgentClient {
    private static final String HOST = "127.0.0.1";
    private static final int CONNECT_TIMEOUT_MS = 2_000;
    private static final int READ_TIMEOUT_MS = 30_000;
    private static final int MAX_RESPONSE_BYTES = 8 * 1024;

    private AgentClient() {}

    private static Path controlFile() {
        return FabricLoader.getInstance().getConfigDir().resolve("mc-tunnel").resolve("control.json");
    }

    private record Endpoint(int port, String token) {}

    /** Read the agent's port + token from control.json, or null if it isn't there yet. */
    private static Endpoint endpoint() {
        try {
            String text = Files.readString(controlFile(), StandardCharsets.UTF_8);
            JsonObject o = JsonParser.parseString(text).getAsJsonObject();
            int port = o.get("port").getAsInt();
            String token = o.get("token").getAsString();
            if (port > 0 && port <= 65535 && !token.isEmpty()) {
                return new Endpoint(port, token);
            }
        } catch (Exception ignored) {
            // missing/unreadable -> no agent yet
        }
        return null;
    }

    public static String endpointDescription() {
        Endpoint e = endpoint();
        return e == null ? HOST + ":(none)" : HOST + ":" + e.port();
    }

    /** Liveness check: is an agent answering on the control port from control.json? */
    public static boolean ping() {
        Endpoint e = endpoint();
        return e != null && pingPort(e.port());
    }

    static boolean pingPort(int port) {
        try (Socket sock = new Socket()) {
            sock.connect(new InetSocketAddress(HOST, port), 500);
            sock.setSoTimeout(1000);
            sock.getOutputStream().write("{\"op\":\"ping\"}\n".getBytes(StandardCharsets.UTF_8));
            sock.getOutputStream().flush();
            String line = readCappedLine(sock);
            return line != null
                    && JsonParser.parseString(line).getAsJsonObject().get("ok").getAsBoolean();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Ask the agent to resolve {@code name} and return a validated loopback
     * {@code "127.0.0.1:<port>"} to connect to, or {@code null} on any failure.
     */
    public static String resolve(String name) {
        // Lazily (re)start the bundled agent if it isn't up yet — retries across joins.
        AgentLauncher.ensureRunning();

        Endpoint e = endpoint();
        if (e == null) {
            McTunnelMod.LOGGER.warn("no mc-tunnel agent control file; cannot resolve {}", name);
            return null;
        }

        JsonObject req = new JsonObject();
        req.addProperty("op", "resolve");
        req.addProperty("name", name);
        req.addProperty("token", e.token());

        try (Socket sock = new Socket()) {
            sock.connect(new InetSocketAddress(HOST, e.port()), CONNECT_TIMEOUT_MS);
            sock.setSoTimeout(READ_TIMEOUT_MS);
            OutputStream out = sock.getOutputStream();
            out.write((req.toString() + "\n").getBytes(StandardCharsets.UTF_8));
            out.flush();

            String line = readCappedLine(sock);
            if (line == null) {
                McTunnelMod.LOGGER.warn("mc-tunnel agent gave no reply for {}", name);
                return null;
            }
            JsonObject resp = JsonParser.parseString(line).getAsJsonObject();
            if (resp.has("ok") && resp.get("ok").getAsBoolean() && resp.has("listen")) {
                String listen = resp.get("listen").getAsString();
                if (!isLoopbackAddress(listen)) {
                    McTunnelMod.LOGGER.warn("agent returned non-loopback address {} for {}; refusing", listen, name);
                    return null;
                }
                McTunnelMod.LOGGER.info("resolved {} -> {}", name, listen);
                return listen;
            }
            String err = resp.has("error") ? resp.get("error").getAsString() : "unknown error";
            McTunnelMod.LOGGER.warn("agent could not resolve {}: {}", name, err);
            return null;
        } catch (Exception ex) {
            McTunnelMod.LOGGER.warn("could not reach mc-tunnel agent for {}: {}", name, ex.getMessage());
            return null;
        }
    }

    /**
     * Ask the agent for the live ping (ms) to the publisher serving {@code name}. Returns the
     * real-time tunnel RTT, or -1 if unknown/unreachable. Cheap; meant to be polled ~1/s.
     */
    public static int rttMs(String name) {
        Endpoint e = endpoint();
        if (e == null) {
            return -1;
        }
        JsonObject req = new JsonObject();
        req.addProperty("op", "rtt");
        req.addProperty("name", name);
        req.addProperty("token", e.token());
        try (Socket sock = new Socket()) {
            sock.connect(new InetSocketAddress(HOST, e.port()), CONNECT_TIMEOUT_MS);
            sock.setSoTimeout(3_000);
            sock.getOutputStream().write((req.toString() + "\n").getBytes(StandardCharsets.UTF_8));
            sock.getOutputStream().flush();
            String line = readCappedLine(sock);
            if (line == null) {
                return -1;
            }
            JsonObject resp = JsonParser.parseString(line).getAsJsonObject();
            if (resp.has("ok") && resp.get("ok").getAsBoolean() && resp.has("rtt_ms")) {
                return resp.get("rtt_ms").getAsInt();
            }
        } catch (Exception ignored) {
            // agent gone / busy -> unknown
        }
        return -1;
    }

    /** Only accept "127.0.0.1:<port>" / "[::1]:<port>" so the agent can't redirect us off-box. */
    static boolean isLoopbackAddress(String listen) {
        int colon = listen.lastIndexOf(':');
        if (colon <= 0 || colon == listen.length() - 1) {
            return false;
        }
        String host = listen.substring(0, colon);
        String portStr = listen.substring(colon + 1);
        if (!host.equals("127.0.0.1") && !host.equals("::1") && !host.equals("[::1]")) {
            return false;
        }
        try {
            int port = Integer.parseInt(portStr);
            return port > 0 && port <= 65535;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /** Read one '\n'-terminated line, capped at MAX_RESPONSE_BYTES so the agent can't flood us. */
    private static String readCappedLine(Socket sock) throws Exception {
        BufferedReader in = new BufferedReader(
                new InputStreamReader(sock.getInputStream(), StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        int c;
        while ((c = in.read()) != -1) {
            if (c == '\n') {
                break;
            }
            sb.append((char) c);
            if (sb.length() > MAX_RESPONSE_BYTES) {
                return null; // oversized -> treat as failure
            }
        }
        return sb.length() == 0 ? null : sb.toString();
    }
}
