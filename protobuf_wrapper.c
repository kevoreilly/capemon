/*
 * capemon protobuf log encoder (nanopb).
 *
 * Builds capemon_HookEvent messages that match CAPEv2's data/capemon_pb.proto.
 * Wired into log.c through the log_serializer_t vtable (g_protobuf_serializer)
 * plus two standalone helpers (protobuf_encode_info / protobuf_encode_debug)
 * for the frames loq() does not build field-by-field.
 */
#include "protobuf_wrapper.h"
#include "log_serializer.h"
#include "utf8.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Provided by log.c - one lazily-allocated context per logging thread. */
extern protobuf_context_t *get_thread_pb_ctx(void);

/* Separator inserted between elements of a flattened %a / %A array argument.
 * repeated bytes cannot nest, so an argv-style argument is joined into a single
 * entry; the CAPE parser splits it back on this byte. */
#define PB_ARRAY_SEP 0x00

/* --- arena ------------------------------------------------------------------ */

static int arena_ensure(protobuf_context_t *ctx, size_t need)
{
    size_t cap = ctx->arg_arena_cap;
    uint8_t *p;

    if (need <= cap)
        return 1;
    if (cap == 0)
        cap = 4096;
    while (cap < need)
        cap *= 2;
    p = (uint8_t *)realloc(ctx->arg_arena, cap);
    if (!p)
        return 0;
    ctx->arg_arena = p;
    ctx->arg_arena_cap = cap;
    return 1;
}

/* Append raw bytes as one new positional argument slot. */
static void arg_push(protobuf_context_t *ctx, const void *buf, size_t len)
{
    if (ctx->arg_count >= PB_MAX_ARGS)
        return;
    if (!arena_ensure(ctx, ctx->arg_arena_len + len + 1))
        return;
    if (len && buf)
        memcpy(ctx->arg_arena + ctx->arg_arena_len, buf, len);
    ctx->args[ctx->arg_count].off = ctx->arg_arena_len;
    ctx->args[ctx->arg_count].len = len;
    ctx->arg_count++;
    ctx->arg_arena_len += len;
}

/* Append bytes to the argument slot currently open for a %a / %A array. */
static void arg_array_append(protobuf_context_t *ctx, const void *buf, size_t len)
{
    pb_arg_slot_t *slot;
    size_t add;

    if (!ctx->arg_count)
        return;
    slot = &ctx->args[ctx->arg_count - 1];
    add = len + (slot->len ? 1 : 0);   /* leading separator except for first */
    if (!arena_ensure(ctx, ctx->arg_arena_len + add))
        return;
    if (slot->len)
        ctx->arg_arena[ctx->arg_arena_len++] = PB_ARRAY_SEP;
    if (len && buf) {
        memcpy(ctx->arg_arena + ctx->arg_arena_len, buf, len);
        ctx->arg_arena_len += len;
    }
    slot->len += add;
}

static void arg_bytes(protobuf_context_t *ctx, const void *buf, size_t len)
{
    if (ctx->in_array)
        arg_array_append(ctx, buf, len);
    else
        arg_push(ctx, buf, len);
}

/* --- encode callbacks ----------------------------------------------------- */

static bool encode_arguments_cb(pb_ostream_t *stream, const pb_field_t *field,
                                void *const *arg)
{
    const protobuf_context_t *ctx = (const protobuf_context_t *)*arg;
    size_t i;

    for (i = 0; i < ctx->arg_count; i++) {
        if (!pb_encode_tag_for_field(stream, field))
            return false;
        if (!pb_encode_string(stream, ctx->arg_arena + ctx->args[i].off,
                              ctx->args[i].len))
            return false;
    }
    return true;
}

/* --- lifecycle ---------------------------------------------------------- */

void protobuf_ctx_reset_call(protobuf_context_t *ctx)
{
    capemon_CallMessage *call;

    if (!ctx)
        return;

    memset(&ctx->event, 0, sizeof(ctx->event));
    ctx->event.which_payload = capemon_HookEvent_call_tag;
    call = &ctx->event.payload.call;
    call->arguments.funcs.encode = encode_arguments_cb;
    call->arguments.arg = ctx;
    /* aux is never populated by capemon */

    ctx->arg_count = 0;
    ctx->arg_arena_len = 0;
    ctx->in_array = 0;
    ctx->encoded_size = 0;
}

size_t protobuf_ctx_finish(protobuf_context_t *ctx)
{
    pb_ostream_t stream;
    size_t need;

    if (!ctx)
        return 0;

    /* Upper bound: every arena byte appears once, plus per-arg tag/len and the
     * fixed scalar fields. 1 KiB slack covers both comfortably. */
    need = ctx->arg_arena_len + 1024;
    if (need > ctx->out_cap) {
        uint8_t *p = (uint8_t *)realloc(ctx->out_buf, need);
        if (!p) {
            ctx->encoded_size = 0;
            return 0;
        }
        ctx->out_buf = p;
        ctx->out_cap = need;
    }

    stream = pb_ostream_from_buffer(ctx->out_buf, ctx->out_cap);
    if (!pb_encode(&stream, capemon_HookEvent_fields, &ctx->event)) {
        ctx->encoded_size = 0;
        return 0;
    }
    ctx->encoded_size = stream.bytes_written;
    return ctx->encoded_size;
}

const uint8_t *protobuf_ctx_data(protobuf_context_t *ctx)
{
    return (ctx && ctx->out_buf) ? ctx->out_buf : (const uint8_t *)"";
}

size_t protobuf_ctx_size(protobuf_context_t *ctx)
{
    return ctx ? ctx->encoded_size : 0;
}

void protobuf_ctx_free(protobuf_context_t *ctx)
{
    if (!ctx)
        return;
    free(ctx->arg_arena);
    free(ctx->out_buf);
    ctx->arg_arena = NULL;
    ctx->out_buf = NULL;
    ctx->arg_arena_cap = ctx->arg_arena_len = 0;
    ctx->out_cap = ctx->encoded_size = 0;
}

/* --- CallMessage field setters ---------------------------------------- */

void protobuf_call_set_int(protobuf_context_t *ctx, const char *name, int32_t val)
{
    capemon_CallMessage *call;
    char buf[16];

    if (!ctx || ctx->event.which_payload != capemon_HookEvent_call_tag)
        return;
    call = &ctx->event.payload.call;

    if (!strcmp(name, "I") || !strcmp(name, "i"))       call->index = val;
    else if (!strcmp(name, "T"))                         call->thread_id = val;
    else if (!strcmp(name, "t"))                         call->timestamp = (uint32_t)val;
    else if (!strcmp(name, "r") || !strcmp(name, "C"))   /* repeat count / caller: no field */ ;
    else if (!strcmp(name, "0"))                         call->is_success = (val != 0);
    else if (!strcmp(name, "1"))                         call->retval = (uint32_t)val;
    else {
        /* scalar integer argument (%i / %h path) - store decimal text */
        int n = _snprintf(buf, sizeof(buf), "%d", val);
        if (n < 0) n = 0;
        arg_bytes(ctx, buf, (size_t)n);
    }
}

void protobuf_call_set_long(protobuf_context_t *ctx, const char *name, int64_t val)
{
    capemon_CallMessage *call;
    char buf[24];

    if (!ctx || ctx->event.which_payload != capemon_HookEvent_call_tag)
        return;
    call = &ctx->event.payload.call;

    if (!strcmp(name, "R"))       call->return_address = (uint64_t)val;
    else if (!strcmp(name, "P"))  call->parent_return_address = (uint64_t)val;
    else if (!strcmp(name, "1"))  call->retval = (uint64_t)val;
    else if (!strcmp(name, "C"))  /* caller: no field */ ;
    else {
        int n = _snprintf(buf, sizeof(buf), "%lld", (long long)val);
        if (n < 0) n = 0;
        arg_bytes(ctx, buf, (size_t)n);
    }
}

void protobuf_call_add_arg_bytes(protobuf_context_t *ctx, const char *name,
                                 const void *buf, size_t len)
{
    (void)name;
    if (ctx && ctx->event.which_payload == capemon_HookEvent_call_tag)
        arg_bytes(ctx, buf, len);
}

void protobuf_call_add_arg_str(protobuf_context_t *ctx, const char *name,
                               const char *val, int length)
{
    size_t n;
    (void)name;
    if (!ctx || ctx->event.which_payload != capemon_HookEvent_call_tag)
        return;
    if (!val) {
        arg_bytes(ctx, "", 0);
        return;
    }
    n = (length < 0) ? strlen(val) : (size_t)length;
    arg_bytes(ctx, val, n);
}

void protobuf_call_add_arg_wstr(protobuf_context_t *ctx, const char *name,
                                const wchar_t *val, int length)
{
    char *utf8s;
    int utf8len;
    (void)name;
    if (!ctx || ctx->event.which_payload != capemon_HookEvent_call_tag)
        return;
    if (!val) {
        arg_bytes(ctx, "", 0);
        return;
    }
    /* utf8_wstring honours an explicit length and returns a 4-byte length
     * prefix followed by the encoded bytes. */
    utf8s = utf8_wstring(val, length);
    if (!utf8s) {
        arg_bytes(ctx, "", 0);
        return;
    }
    utf8len = *(int *)utf8s;
    arg_bytes(ctx, utf8s + 4, (size_t)utf8len);
    free(utf8s);
}

void protobuf_call_array_begin(protobuf_context_t *ctx)
{
    if (!ctx)
        return;
    ctx->in_array = 1;
    arg_push(ctx, "", 0);          /* open a single accumulating slot */
}

void protobuf_call_array_end(protobuf_context_t *ctx)
{
    if (ctx)
        ctx->in_array = 0;
}

/* --- standalone frames ------------------------------------------------- */

size_t protobuf_encode_info(uint8_t *out, size_t out_cap,
                            int32_t index, const char *name, const char *category,
                            const char *const *arg_names, const char *const *arg_types,
                            size_t arg_n)
{
    capemon_HookEvent ev;
    capemon_InfoMessage *info;
    pb_ostream_t st;
    size_t i;

    memset(&ev, 0, sizeof(ev));
    ev.which_payload = capemon_HookEvent_info_tag;
    info = &ev.payload.info;
    info->index = index;
    if (name)
        strncpy(info->name, name, sizeof(info->name) - 1);
    if (category)
        strncpy(info->category, category, sizeof(info->category) - 1);

    if (arg_n > 40)               /* schema.options: max_count:40 */
        arg_n = 40;
    info->args_count = (pb_size_t)arg_n;
    for (i = 0; i < arg_n; i++) {
        if (arg_names && arg_names[i])
            strncpy(info->args[i].name, arg_names[i], sizeof(info->args[i].name) - 1);
        if (arg_types && arg_types[i])
            strncpy(info->args[i].type, arg_types[i], sizeof(info->args[i].type) - 1);
    }

    st = pb_ostream_from_buffer(out, out_cap);
    if (!pb_encode(&st, capemon_HookEvent_fields, &ev))
        return 0;
    return st.bytes_written;
}

size_t protobuf_encode_debug(uint8_t *out, size_t out_cap, const char *message)
{
    capemon_HookEvent ev;
    pb_ostream_t st;

    memset(&ev, 0, sizeof(ev));
    ev.which_payload = capemon_HookEvent_debug_tag;
    if (message)
        strncpy(ev.payload.debug.message, message, sizeof(ev.payload.debug.message) - 1);

    st = pb_ostream_from_buffer(out, out_cap);
    if (!pb_encode(&st, capemon_HookEvent_fields, &ev))
        return 0;
    return st.bytes_written;
}

/* --- log_serializer_t vtable ---------------------------------------------- */

static void pb_v_init(void)                { protobuf_ctx_reset_call(get_thread_pb_ctx()); }
static void pb_v_int(const char *n, int32_t v)  { protobuf_call_set_int(get_thread_pb_ctx(), n, v); }
static void pb_v_long(const char *n, int64_t v) { protobuf_call_set_long(get_thread_pb_ctx(), n, v); }
static void pb_v_str(const char *n, const char *v, int len)     { protobuf_call_add_arg_str(get_thread_pb_ctx(), n, v, len); }
static void pb_v_wstr(const char *n, const wchar_t *v, int len) { protobuf_call_add_arg_wstr(get_thread_pb_ctx(), n, v, len); }
static void pb_v_bin(const char *n, const void *b, size_t l)    { protobuf_call_add_arg_bytes(get_thread_pb_ctx(), n, b, l); }
static void pb_v_finish(void)              { protobuf_ctx_finish(get_thread_pb_ctx()); }
static void pb_v_arr_begin(const char *n)  { if (strcmp(n, "args") != 0) protobuf_call_array_begin(get_thread_pb_ctx()); }
static void pb_v_arr_end(void)             { protobuf_context_t *c = get_thread_pb_ctx(); if (c && c->in_array) protobuf_call_array_end(c); }
static const uint8_t *pb_v_data(void)      { return protobuf_ctx_data(get_thread_pb_ctx()); }
static size_t pb_v_size(void)              { return protobuf_ctx_size(get_thread_pb_ctx()); }
static void pb_v_destroy(void)             { /* buffers are reused; freed in TlsThreadCleanup */ }

log_serializer_t g_protobuf_serializer = {
    .init = pb_v_init,
    .append_int = pb_v_int,
    .append_long = pb_v_long,
    .append_string = pb_v_str,
    .append_wstring = pb_v_wstr,
    .append_binary = pb_v_bin,
    .append_finish = pb_v_finish,
    .append_start_array = pb_v_arr_begin,
    .append_finish_array = pb_v_arr_end,
    .get_data = pb_v_data,
    .get_size = pb_v_size,
    .destroy = pb_v_destroy
};
