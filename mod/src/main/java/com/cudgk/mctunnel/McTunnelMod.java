package com.cudgk.mctunnel;

import net.fabricmc.api.ClientModInitializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Client entrypoint. The real work happens in {@link com.cudgk.mctunnel.mixin.ServerAddressMixin},
 * which intercepts {@code xxxx.minecraft} addresses and rewrites them to a local port served
 * by the {@code mc-tunnel agent}. This mod holds no keys and speaks only to the local agent.
 */
public class McTunnelMod implements ClientModInitializer {
    public static final Logger LOGGER = LoggerFactory.getLogger("mc-tunnel");

    @Override
    public void onInitializeClient() {
        LOGGER.info("mc-tunnel client starting; .minecraft addresses resolve via the local agent on {}",
                AgentClient.endpointDescription());
        // Start the bundled daemon off-thread so we don't block game init. By the time the
        // player navigates to the server list and clicks Join, it's ready.
        Thread t = new Thread(AgentLauncher::ensureRunning, "mc-tunnel-agent-launcher");
        t.setDaemon(true);
        t.start();
        // Poll the live tunnel ping for the HUD.
        TunnelPing.startPoller();
    }
}
