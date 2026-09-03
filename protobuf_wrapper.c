#include "protobuf_wrapper.h"
#include "log_serializer.h"
#include "utf8.h"
#include <string.h>
#include <stdlib.h>

// String callback functions for nanopb
static bool encode_string_callback(pb_ostream_t *stream, const pb_field_t *field, void * const *arg) {
    const char *str = (const char*)*arg;
    if (!str) return true;
    
    size_t len = strlen(str);
    if (!pb_encode_tag_for_field(stream, field))
        return false;
        
    return pb_encode_string(stream, (const uint8_t*)str, len);
}

// Binary callback functions for nanopb
static bool encode_binary_callback(pb_ostream_t *stream, const pb_field_t *field, void * const *arg) {
    const pb_binary_t *bin = (const pb_binary_t *)*arg;
    if (!bin || !bin->ptr || bin->len == 0) return true;
    
    if (!pb_encode_tag_for_field(stream, field))
        return false;
        
    return pb_encode_string(stream, bin->ptr, bin->len);
}

void protobuf_init(protobuf_context_t* ctx, int message_type) {
    // Zero the entire structure first
    memset(ctx, 0, sizeof(protobuf_context_t));
    
    // Initialize nanopb structs manually for MSVC compatibility
    ctx->event.which_message_type = message_type;
    
    if (message_type == HookEvent_regular_call_tag) {
        RegularCall* call = &ctx->event.message_type.regular_call;
        call->i = 0;
        call->t = 0;
        call->r = 0;
        call->p = 0;
    } else if (message_type == HookEvent_str_tag) {
        StrMessage* str_msg = &ctx->event.message_type.str;
        str_msg->i = 0;
    }
}

void protobuf_finish(protobuf_context_t* ctx) {
    pb_ostream_t stream = pb_ostream_from_buffer(ctx->buffer, sizeof(ctx->buffer));
    if (pb_encode(&stream, HookEvent_fields, &ctx->event)) {
        ctx->encoded_size = stream.bytes_written;
    } else {
        ctx->encoded_size = 0;
    }
}

// Copy at most `length` bytes (or strlen(str) when length < 0) into the scratch
// arena and NUL-terminate. Honouring an explicit length is required: callers
// pass counted, non-NUL-terminated buffers (%S / UNICODE_STRING / registry
// values) and a strlen() here would over-read process memory.
static const char* copy_to_scratch_n(protobuf_context_t* ctx, const char* str, int length) {
    size_t len;
    char *dest;
    if (!str) return NULL;
    len = (length < 0) ? strlen(str) : (size_t)length;
    if (ctx->scratch_offset + len + 1 > sizeof(ctx->string_scratch)) {
        // Out of scratch space. The value is dropped - acceptable only because
        // the protobuf backend is explicitly experimental/lossy (see log_init).
        return NULL;
    }
    dest = ctx->string_scratch + ctx->scratch_offset;
    memcpy(dest, str, len);
    dest[len] = '\0';
    ctx->scratch_offset += len + 1;
    return dest;
}

int protobuf_append_string(protobuf_context_t* ctx, const char* name, const char* value, int length) {
    if (!value) return 0;

    const char *copied_val = copy_to_scratch_n(ctx, value, length);
    if (!copied_val) return 0;
    
    if (ctx->event.which_message_type == HookEvent_str_tag) {
        StrMessage* str_msg = &ctx->event.message_type.str;
        
        if (strcmp(name, "name") == 0) {
            str_msg->name.funcs.encode = encode_string_callback;
            str_msg->name.arg = (void*)copied_val;
        } else if (strcmp(name, "type") == 0) {
            str_msg->type.funcs.encode = encode_string_callback;
            str_msg->type.arg = (void*)copied_val;
        } else if (strcmp(name, "category") == 0) {
            str_msg->category.funcs.encode = encode_string_callback;
            str_msg->category.arg = (void*)copied_val;
        } else if (strcmp(name, "api_name") == 0) {
            str_msg->api_name.funcs.encode = encode_string_callback;
            str_msg->api_name.arg = (void*)copied_val;
        }
    } else if (ctx->event.which_message_type == HookEvent_regular_call_tag) {
        RegularCall* call = &ctx->event.message_type.regular_call;
        if (strcmp(name, "c") == 0) {
            call->c.funcs.encode = encode_string_callback;
            call->c.arg = (void*)copied_val;
        }
    }
    
    return 1;
}

int protobuf_append_wstring(protobuf_context_t* ctx, const char* name, const wchar_t* value, int length) {
    int ret, utf8len;
    char *utf8s;
    if (!value) return 0;

    // utf8_wstring() honours an explicit length (encodes exactly `length` wide
    // chars) and returns a 4-byte length prefix followed by the encoded bytes.
    utf8s = utf8_wstring(value, length);
    if (!utf8s) return 0;

    utf8len = *(int*)utf8s;
    ret = protobuf_append_string(ctx, name, utf8s + 4, utf8len);
    free(utf8s);
    return ret;
}

int protobuf_append_int(protobuf_context_t* ctx, const char* name, int32_t value) {
    if (ctx->event.which_message_type == HookEvent_regular_call_tag) {
        RegularCall* call = &ctx->event.message_type.regular_call;

        if (strcmp(name, "I") == 0 || strcmp(name, "i") == 0) {
            call->i = value;
        } else if (strcmp(name, "t") == 0) {
            // Elapsed-tick field. NOTE: the thread id ("T") has no field in the
            // current schema - it is intentionally dropped rather than
            // overwriting the timestamp.
            call->t = value;
        }
    } else if (ctx->event.which_message_type == HookEvent_str_tag) {
        StrMessage* str_msg = &ctx->event.message_type.str;
        
        if (strcmp(name, "I") == 0 || strcmp(name, "i") == 0) {
            str_msg->i = value;
        }
    }
    
    return 1;
}

int protobuf_append_long(protobuf_context_t* ctx, const char* name, int64_t value) {
    if (ctx->event.which_message_type == HookEvent_regular_call_tag) {
        RegularCall* call = &ctx->event.message_type.regular_call;
        if (strcmp(name, "R") == 0 || strcmp(name, "r") == 0) {
            call->r = (uint64_t)value;
        } else if (strcmp(name, "P") == 0 || strcmp(name, "p") == 0) {
            call->p = (uint64_t)value;
        }
    }
    return 1;
}

int protobuf_append_binary(protobuf_context_t* ctx, const char* name, const void* buf, size_t len) {
    if (!buf || len == 0) return 0;

    if (ctx->scratch_offset + len > sizeof(ctx->string_scratch)) {
        // Scratch exhausted: a large %c buffer, or several buffers in one call,
        // can exceed string_scratch (32 KB). The value is dropped. Acceptable
        // only under the experimental/lossy protobuf banner (see log_init);
        // a finalised schema should size or grow this arena to match
        // large_buffer_log_max.
        return 0;
    }

    uint8_t *copied_buf = (uint8_t *)(ctx->string_scratch + ctx->scratch_offset);
    memcpy(copied_buf, buf, len);
    ctx->scratch_offset += len;
    
    if (ctx->event.which_message_type == HookEvent_regular_call_tag) {
        RegularCall* call = &ctx->event.message_type.regular_call;
        if (strcmp(name, "args") == 0) {
            ctx->bin_args.ptr = copied_buf;
            ctx->bin_args.len = len;
            call->args.funcs.encode = encode_binary_callback;
            call->args.arg = &ctx->bin_args;
        } else if (strcmp(name, "data") == 0) {
            ctx->bin_data.ptr = copied_buf;
            ctx->bin_data.len = len;
            call->data.funcs.encode = encode_binary_callback;
            call->data.arg = &ctx->bin_data;
        } else if (strcmp(name, "c") == 0) {
            ctx->bin_c.ptr = copied_buf;
            ctx->bin_c.len = len;
            call->c.funcs.encode = encode_binary_callback;
            call->c.arg = &ctx->bin_c;
        } else if (strcmp(name, "index") == 0) {
            ctx->bin_index.ptr = copied_buf;
            ctx->bin_index.len = len;
            call->index.funcs.encode = encode_binary_callback;
            call->index.arg = &ctx->bin_index;
        } else if (strcmp(name, "aux") == 0) {
            ctx->bin_aux.ptr = copied_buf;
            ctx->bin_aux.len = len;
            call->aux.funcs.encode = encode_binary_callback;
            call->aux.arg = &ctx->bin_aux;
        }
    } else if (ctx->event.which_message_type == HookEvent_str_tag) {
        StrMessage* str_msg = &ctx->event.message_type.str;
        if (strcmp(name, "args") == 0) {
            ctx->bin_args.ptr = copied_buf;
            ctx->bin_args.len = len;
            str_msg->args.funcs.encode = encode_binary_callback;
            str_msg->args.arg = &ctx->bin_args;
        } else if (strcmp(name, "arguments") == 0) {
            ctx->bin_data.ptr = copied_buf;
            ctx->bin_data.len = len;
            str_msg->arguments.funcs.encode = encode_binary_callback;
            str_msg->arguments.arg = &ctx->bin_data;
        }
    }
    
    return 1;
}

size_t protobuf_size(protobuf_context_t* ctx) {
    return ctx->encoded_size;
}

const uint8_t* protobuf_data(protobuf_context_t* ctx) {
    return ctx->buffer;
}

void protobuf_destroy(protobuf_context_t* ctx) {
    // No dynamic memory was allocated inside context, so we just clean up
    memset(ctx, 0, sizeof(protobuf_context_t));
}

// Strategy Pattern Implementation
extern protobuf_context_t* get_thread_pb_ctx(void);

static void pb_serializer_init(void) {
    protobuf_context_t* ctx = get_thread_pb_ctx();
    if (ctx) protobuf_init(ctx, HookEvent_regular_call_tag);
}

static void pb_serializer_append_int(const char *name, int32_t val) {
    protobuf_context_t* ctx = get_thread_pb_ctx();
    if (ctx) protobuf_append_int(ctx, name, val);
}

static void pb_serializer_append_long(const char *name, int64_t val) {
    protobuf_context_t* ctx = get_thread_pb_ctx();
    if (ctx) protobuf_append_long(ctx, name, val);
}

static void pb_serializer_append_string(const char *name, const char *val, int length) {
    protobuf_context_t* ctx = get_thread_pb_ctx();
    if (!ctx) return;
    if (strcmp(name, "type") == 0 || strcmp(name, "category") == 0) {
        ctx->event.which_message_type = HookEvent_str_tag;
    }
    protobuf_append_string(ctx, name, val, length);
}

static void pb_serializer_append_wstring(const char *name, const wchar_t *val, int length) {
    protobuf_context_t* ctx = get_thread_pb_ctx();
    if (ctx) protobuf_append_wstring(ctx, name, val, length);
}

static void pb_serializer_append_binary(const char *name, const void *buf, size_t len) {
    protobuf_context_t* ctx = get_thread_pb_ctx();
    if (ctx) protobuf_append_binary(ctx, name, buf, len);
}

static void pb_serializer_finish(void) {
    protobuf_context_t* ctx = get_thread_pb_ctx();
    if (ctx) protobuf_finish(ctx);
}

static void pb_serializer_append_start_array(const char *name) {
    // Array nesting is handled implicitly by protobuf message schemas
}

static void pb_serializer_append_finish_array(void) {
    // Array nesting is handled implicitly by protobuf message schemas
}

static const uint8_t* pb_serializer_get_data(void) {
    protobuf_context_t* ctx = get_thread_pb_ctx();
    return ctx ? protobuf_data(ctx) : NULL;
}

static size_t pb_serializer_get_size(void) {
    protobuf_context_t* ctx = get_thread_pb_ctx();
    return ctx ? protobuf_size(ctx) : 0;
}

static void pb_serializer_destroy(void) {
    protobuf_context_t* ctx = get_thread_pb_ctx();
    if (ctx) protobuf_destroy(ctx);
}

log_serializer_t g_protobuf_serializer = {
    .init = pb_serializer_init,
    .append_int = pb_serializer_append_int,
    .append_long = pb_serializer_append_long,
    .append_string = pb_serializer_append_string,
    .append_wstring = pb_serializer_append_wstring,
    .append_binary = pb_serializer_append_binary,
    .append_finish = pb_serializer_finish,
    .append_start_array = pb_serializer_append_start_array,
    .append_finish_array = pb_serializer_append_finish_array,
    .get_data = pb_serializer_get_data,
    .get_size = pb_serializer_get_size,
    .destroy = pb_serializer_destroy
};
