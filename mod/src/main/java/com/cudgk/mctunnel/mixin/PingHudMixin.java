package com.cudgk.mctunnel.mixin;

import com.cudgk.mctunnel.TunnelPing;
import net.minecraft.client.MinecraftClient;
import net.minecraft.client.font.TextRenderer;
import net.minecraft.client.gui.DrawContext;
import net.minecraft.client.gui.hud.InGameHud;
import net.minecraft.client.network.PlayerListEntry;
import net.minecraft.client.render.RenderTickCounter;
import net.minecraft.text.Text;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

import java.lang.reflect.Method;

/**
 * Draws the player's ping (the server-reported keep-alive RTT = latency through the whole
 * tunnel) bigger than normal, at the right edge, vertically centered, color-coded.
 *
 * Why so much reflection: the GUI API diverged across the 1.21 line —
 * {@code DrawContext.drawTextWithShadow} changed return type (int → void), and
 * {@code getMatrices()} changed return type (MatrixStack → joml Matrix3x2fStack with
 * different method names). A *compiled* call against one version crashes on the other
 * (NoSuchMethodError). Invoking by name + parameter types (return type ignored) and trying
 * both the dev (named) and production (intermediary) method names keeps one jar working
 * across 1.21.x. Everything is wrapped so the render thread can never be taken down.
 */
@Mixin(InGameHud.class)
public class PingHudMixin {

    private static final float SCALE = 1.6f;
    private static final int RIGHT_MARGIN = 5;

    @Inject(method = "render", at = @At("TAIL"), require = 0)
    private void mctunnel$drawPing(DrawContext context, RenderTickCounter tickCounter, CallbackInfo ci) {
        MinecraftClient client = MinecraftClient.getInstance();
        if (client.player == null || client.getNetworkHandler() == null) {
            return;
        }
        if (client.options != null && client.options.hudHidden) {
            return;
        }
        PlayerListEntry entry = client.getNetworkHandler().getPlayerListEntry(client.player.getUuid());
        if (entry == null) {
            return;
        }
        // Prefer the agent's live tunnel RTT (~1s updates); fall back to MC's keep-alive
        // ping (~15s, averaged) when not on a tunneled server or the agent isn't reachable.
        int realtime = TunnelPing.rttMs();
        int ping = realtime >= 0 ? realtime : entry.getLatency();
        int color = ping < 80 ? 0xFF55FF55 : ping < 200 ? 0xFFFFFF55 : 0xFFFF5555;
        Text text = Text.literal("⚡ " + ping + " ms");
        TextRenderer tr = client.textRenderer;

        Object matrices = invoke(context, getMatrices(context));
        boolean pushed = matrices != null && callNoArg(matrices, "pushMatrix", "push");
        if (pushed) {
            scale(matrices, SCALE);
        }
        float s = pushed ? SCALE : 1f; // if we couldn't scale, fall back to 1x so it still shows

        int tw = tr.getWidth(text);
        int sw = context.getScaledWindowWidth();
        int sh = context.getScaledWindowHeight();
        int x = Math.round((sw - RIGHT_MARGIN) / s) - tw;
        int y = Math.round(sh / (2f * s)) - 5;
        drawShadowed(context, tr, text, x, y, color);

        if (pushed) {
            callNoArg(matrices, "popMatrix", "pop");
        }
    }

    // ---- reflective shims (cached) ----

    private static Method getMatricesMethod;
    private static boolean getMatricesResolved;

    private static Method getMatrices(DrawContext ctx) {
        if (!getMatricesResolved) {
            getMatricesResolved = true;
            for (String name : new String[] {"getMatrices", "method_51448"}) {
                try {
                    getMatricesMethod = DrawContext.class.getMethod(name);
                    break;
                } catch (Throwable ignored) {
                }
            }
        }
        return getMatricesMethod;
    }

    private static Object invoke(DrawContext ctx, Method m) {
        if (m == null) {
            return null;
        }
        try {
            return m.invoke(ctx);
        } catch (Throwable e) {
            return null;
        }
    }

    /** Call a no-arg method on `target` by the first name that resolves. */
    private static boolean callNoArg(Object target, String... names) {
        for (String name : names) {
            try {
                Method m = target.getClass().getMethod(name);
                m.invoke(target);
                return true;
            } catch (Throwable ignored) {
            }
        }
        return false;
    }

    /** Scale the matrix uniformly, trying the various arities across MatrixStack / joml. */
    private static void scale(Object matrices, float f) {
        // MatrixStack.scale(float,float,float); joml Matrix3x2f(Stack).scale(float,float) or scale(float).
        Class<?>[][] sigs = {
            {float.class, float.class, float.class},
            {float.class, float.class},
            {float.class},
        };
        Object[][] args = {
            {f, f, f},
            {f, f},
            {f},
        };
        for (String name : new String[] {"scale", "method_22905"}) {
            for (int i = 0; i < sigs.length; i++) {
                try {
                    Method m = matrices.getClass().getMethod(name, sigs[i]);
                    m.invoke(matrices, args[i]);
                    return;
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private static Method drawMethod;
    private static boolean drawResolved;

    private static void drawShadowed(DrawContext ctx, TextRenderer tr, Text text, int x, int y, int color) {
        if (!drawResolved) {
            drawResolved = true;
            for (String name : new String[] {"drawTextWithShadow", "method_27535"}) {
                try {
                    drawMethod = DrawContext.class.getMethod(
                            name, TextRenderer.class, Text.class, int.class, int.class, int.class);
                    break;
                } catch (Throwable ignored) {
                }
            }
        }
        if (drawMethod == null) {
            return;
        }
        try {
            drawMethod.invoke(ctx, tr, text, x, y, color);
        } catch (Throwable ignored) {
        }
    }
}
