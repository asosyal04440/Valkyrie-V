#ifndef VALKYRIE_V_H
#define VALKYRIE_V_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VALKYRIE_INVALID_HANDLE ((uint8_t)0xFF)

typedef struct valkyrie_bridge_config {
    uint32_t vcpu_count;
    uint32_t memory_mb;
    uint64_t kernel_ptr;
    uint64_t kernel_len;
    uint8_t  mac_addr[6];
    uint8_t  _pad[2];
} valkyrie_bridge_config;

typedef enum valkyrie_bridge_status {
    VALKYRIE_BRIDGE_IDLE       = 0,
    VALKYRIE_BRIDGE_FETCHING   = 1,
    VALKYRIE_BRIDGE_VALIDATING = 2,
    VALKYRIE_BRIDGE_LOADING    = 3,
    VALKYRIE_BRIDGE_LAUNCHING  = 4,
    VALKYRIE_BRIDGE_RUNNING    = 5,
    VALKYRIE_BRIDGE_SUSPENDED  = 6,
    VALKYRIE_BRIDGE_FAULT      = 7,
} valkyrie_bridge_status;

uint8_t valkyrie_init(const valkyrie_bridge_config* cfg);
uint8_t valkyrie_tick(uint8_t handle);
void    valkyrie_begin_fetch(uint8_t handle, size_t total_size);
void    valkyrie_receive_chunk(uint8_t handle, const uint8_t* buf, size_t len);
void    valkyrie_set_sig(uint8_t handle, const uint8_t* sig_32bytes);
bool    valkyrie_net_inject(uint8_t handle, const uint8_t* buf, size_t len);

bool    valkyrie_gpu_submit(uint8_t handle, const uint8_t* cmdbuf, size_t len);
size_t  valkyrie_gpu_pop(uint8_t handle, uint8_t* dst, size_t dst_len);

uint32_t valkyrie_snapshot(uint8_t handle);
uint8_t  valkyrie_status(uint8_t handle);
void     valkyrie_destroy(uint8_t handle);

uint32_t valkyrie_abi_version(void);
void     valkyrie_framebuffer_init(uint64_t base, uint32_t width, uint32_t height, uint32_t stride);
uint32_t valkyrie_gpu_submit_batch(const uint8_t* cmds, size_t len);
uint32_t valkyrie_gpu_flush(void);

/* ABI v2 lock-free completion API (non-blocking). */
uint32_t valkyrie_gpu_completion_latest(void);
bool     valkyrie_gpu_completion_poll(uint32_t next_seq, uint32_t* out_fence);

#ifdef __cplusplus
}
#endif

#endif /* VALKYRIE_V_H */
