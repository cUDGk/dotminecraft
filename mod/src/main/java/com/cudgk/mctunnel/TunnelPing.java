package com.cudgk.mctunnel;

import net.minecraft.client.MinecraftClient;

/**
 * Polls the local agent ~once a second for the live tunnel RTT to the current
 * {@code .minecraft} server and caches it for the HUD. Runs off-thread so the network call
 * never touches the render thread. Returns -1 when not on a tunneled server (the HUD then
 * falls back to Minecraft's own keep-alive ping).
 */
public final class TunnelPing {

    private static volatile int rttMs = -1;
    private static boolean started;

    private TunnelPing() {}

    public static int rttMs() {
        return rttMs;
    }

    public static synchronized void startPoller() {
        if (started) {
            return;
        }
        started = true;
        Thread t = new Thread(() -> {
            while (true) {
                try {
                    String name = currentTunnelName();
                    rttMs = (name != null) ? AgentClient.rttMs(name) : -1;
                } catch (Throwable ignored) {
                    rttMs = -1;
                }
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    return;
                }
            }
        }, "mc-tunnel-ping-poller");
        t.setDaemon(true);
        t.start();
    }

    /** The address of the current server iff it's a tunneled `.minecraft` one, else null. */
    private static String currentTunnelName() {
        try {
            MinecraftClient mc = MinecraftClient.getInstance();
            if (mc.world == null || mc.getCurrentServerEntry() == null) {
                return null;
            }
            String addr = mc.getCurrentServerEntry().address;
            if (addr != null && addr.toLowerCase().endsWith(".minecraft")) {
                return addr;
            }
        } catch (Throwable ignored) {
            // version drift on getCurrentServerEntry/address -> treat as not tunneled
        }
        return null;
    }
}
