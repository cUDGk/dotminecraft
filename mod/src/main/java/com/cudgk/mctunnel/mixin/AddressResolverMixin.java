package com.cudgk.mctunnel.mixin;

import com.cudgk.mctunnel.AgentClient;
import net.minecraft.client.network.Address;
import net.minecraft.client.network.AllowedAddressResolver;
import net.minecraft.client.network.ServerAddress;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

import java.net.InetSocketAddress;
import java.util.Optional;

/**
 * Resolves {@code [vanity.]keyid.minecraft} addresses to the local tunnel port the
 * {@code mc-tunnel agent} serves them on.
 *
 * We hook {@link AllowedAddressResolver#resolve} rather than {@code ServerAddress.parse}
 * on purpose: this runs on the connector / server-list-pinger thread (see {@code
 * ConnectScreen$1}), so the (potentially multi-second) DHT lookup never blocks the render
 * thread. The Minecraft handshake itself is untouched — we just hand back a
 * {@code 127.0.0.1:<port>} Address (SPEC §6.3).
 *
 * Multi-version: the target (intermediary {@code class_6370.method_36907}) is stable across
 * the whole 1.21.x line, so this one jar works on 1.21.1 through 1.21.11+. {@code require = 0}
 * makes a hypothetical signature change degrade to "no rewrite" rather than crash.
 */
@Mixin(AllowedAddressResolver.class)
public class AddressResolverMixin {

    @Inject(method = "resolve", at = @At("HEAD"), cancellable = true, require = 0)
    private void mctunnel$resolve(ServerAddress address, CallbackInfoReturnable<Optional<Address>> cir) {
        String host = address.getAddress();
        if (host == null || !host.toLowerCase().endsWith(".minecraft")) {
            return; // not ours; let Minecraft resolve normally
        }

        String local = AgentClient.resolve(host); // "127.0.0.1:<port>" or null
        if (local == null) {
            // Resolution failed; report unresolved rather than falling through to a
            // doomed DNS lookup for a .minecraft TLD.
            cir.setReturnValue(Optional.empty());
            return;
        }

        int colon = local.lastIndexOf(':');
        String h = local.substring(0, colon);
        int p = Integer.parseInt(local.substring(colon + 1));
        cir.setReturnValue(Optional.of(Address.create(new InetSocketAddress(h, p))));
    }
}
