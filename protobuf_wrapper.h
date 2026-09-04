#ifndef PROTOBUF_WRAPPER_H
#define PROTOBUF_WRAPPER_H

#include "schema.pb.h"
#include "nanopb/pb_encode.h"
#include "nanopb/pb_decode.h"
#include <stddef.h>
#include <stdint.h>

/*
 * Per-thread protobuf encoder state for the CAPE hook log.
 *
 * Only CallMessage.arguments is dynamic: each logged argument is copied into
 * arg_arena (a heap buffer that grows as needed) and recorded as an
 * (offset,len) slot. A single nanopb encode callback walks the slots and emits
 * one length-delimited `bytes` entry per argument, in order. Storing offsets
 * rather than pointers keeps the slots valid across an arena realloc.
 *
 * InfoMessage / ProcessMessage / DebugMessage are bounded static structs
 * (see schema.options) and need no callbacks.
 */

#define PB_MAX_ARGS 64          /* positional args per call we will encode      */

typedef struct {
    size_t off;                 /* offset into arg_arena                        */
    size_t len;                 /* byte length of this argument                 */
} pb_arg_slot_t;

typedef struct {
    capemon_HookEvent event;

    /* dynamic storage for CallMessage.arguments */
    pb_arg_slot_t args[PB_MAX_ARGS];
    size_t arg_count;
    uint8_t *arg_arena;
    size_t arg_arena_len;
    size_t arg_arena_cap;

    /* scratch used only while emitting a nested %a / %A argument */
    int in_array;
    size_t array_start_off;     /* offset in arg_arena where the array began    */

    /* encode output */
    uint8_t *out_buf;
    size_t out_cap;
    size_t encoded_size;
} protobuf_context_t;

/* Lifecycle ---------------------------------------------------------------- */
void   protobuf_ctx_reset_call(protobuf_context_t *ctx);   /* begin a CallMessage */
size_t protobuf_ctx_finish(protobuf_context_t *ctx);       /* encode -> out_buf   */
const uint8_t *protobuf_ctx_data(protobuf_context_t *ctx);
size_t protobuf_ctx_size(protobuf_context_t *ctx);
void   protobuf_ctx_free(protobuf_context_t *ctx);         /* release heap buffers */

/* CallMessage field setters (called through the log_serializer_t vtable) --- */
void protobuf_call_set_int(protobuf_context_t *ctx, const char *name, int32_t val);
void protobuf_call_set_long(protobuf_context_t *ctx, const char *name, int64_t val);
void protobuf_call_add_arg_bytes(protobuf_context_t *ctx, const char *name,
                                 const void *buf, size_t len);
void protobuf_call_add_arg_str(protobuf_context_t *ctx, const char *name,
                               const char *val, int length);
void protobuf_call_add_arg_wstr(protobuf_context_t *ctx, const char *name,
                                const wchar_t *val, int length);
void protobuf_call_array_begin(protobuf_context_t *ctx);
void protobuf_call_array_end(protobuf_context_t *ctx);

/* Standalone frames written directly to the result server (not via loq) ---- */
/* Returns encoded length in `out` (caller-provided buffer) or 0 on failure.  */
size_t protobuf_encode_info(uint8_t *out, size_t out_cap,
                            int32_t index, const char *name, const char *category,
                            const char *const *arg_names, const char *const *arg_types,
                            size_t arg_n);
size_t protobuf_encode_debug(uint8_t *out, size_t out_cap, const char *message);

#endif
