#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "valkyrie_v.h"

typedef struct echos_valkyrie_ctx {
    uint8_t handle;
    uint32_t completion_seq;
} echos_valkyrie_ctx;

typedef void (*echos_fence_cb)(uint32_t fence_id, void* user_data);

static inline bool echos_valkyrie_abi_ok(void) {
    return valkyrie_abi_version() >= 2;
}

bool echos_valkyrie_init(
    echos_valkyrie_ctx* ctx,
    const valkyrie_bridge_config* cfg,
    uint64_t fb_base,
    uint32_t fb_width,
    uint32_t fb_height,
    uint32_t fb_stride
) {
    if (ctx == NULL || cfg == NULL) {
        return false;
    }
    if (!echos_valkyrie_abi_ok()) {
        return false;
    }

    ctx->handle = valkyrie_init(cfg);
    if (ctx->handle == VALKYRIE_INVALID_HANDLE) {
        return false;
    }

    valkyrie_framebuffer_init(fb_base, fb_width, fb_height, fb_stride);
    ctx->completion_seq = valkyrie_gpu_completion_latest();
    return true;
}

void echos_valkyrie_shutdown(echos_valkyrie_ctx* ctx) {
    if (ctx == NULL) {
        return;
    }
    if (ctx->handle != VALKYRIE_INVALID_HANDLE) {
        valkyrie_destroy(ctx->handle);
        ctx->handle = VALKYRIE_INVALID_HANDLE;
    }
}

/*
 * Called from echOS scheduler tick; never blocks.
 * Returns current bridge status.
 */
uint8_t echos_valkyrie_tick(echos_valkyrie_ctx* ctx) {
    if (ctx == NULL || ctx->handle == VALKYRIE_INVALID_HANDLE) {
        return VALKYRIE_BRIDGE_FAULT;
    }
    return valkyrie_tick(ctx->handle);
}

/*
 * Submit a UGCommand byte stream and flush once. Non-blocking.
 */
uint32_t echos_valkyrie_submit_and_flush(const uint8_t* cmds, size_t cmds_len) {
    uint32_t submitted = valkyrie_gpu_submit_batch(cmds, cmds_len);
    (void)valkyrie_gpu_flush();
    return submitted;
}

/*
 * Drain completion events [ctx->completion_seq + 1, latest].
 * No spin, no blocking; caller controls call frequency.
 */
uint32_t echos_valkyrie_poll_completions(
    echos_valkyrie_ctx* ctx,
    echos_fence_cb on_fence,
    void* user_data
) {
    if (ctx == NULL) {
        return 0;
    }

    uint32_t latest = valkyrie_gpu_completion_latest();
    uint32_t handled = 0;

    while (ctx->completion_seq < latest) {
        uint32_t next_seq = ctx->completion_seq + 1;
        uint32_t fence_id = 0;
        if (!valkyrie_gpu_completion_poll(next_seq, &fence_id)) {
            break;
        }

        ctx->completion_seq = next_seq;
        handled += 1;

        if (on_fence != NULL) {
            on_fence(fence_id, user_data);
        }
    }

    return handled;
}
