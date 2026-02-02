#include "protobuf_wrapper.h"
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

void protobuf_init(protobuf_context_t* ctx) {
    // Zero the entire structure first
    memset(ctx, 0, sizeof(protobuf_context_t));
    
    // Initialize nanopb structs manually for MSVC compatibility
    ctx->event.which_message_type = HookEvent_regular_call_tag;
    
    // Manually initialize the regular_call message
    ctx->event.message_type.regular_call.i = 0;
    ctx->event.message_type.regular_call.t = 0;
    ctx->event.message_type.regular_call.r = 0;
    ctx->event.message_type.regular_call.p = 0;
    
    // Initialize string callbacks to NULL
    ctx->event.message_type.regular_call.c.funcs.encode = NULL;
    ctx->event.message_type.regular_call.c.arg = NULL;
    ctx->event.message_type.regular_call.args.funcs.encode = NULL;
    ctx->event.message_type.regular_call.args.arg = NULL;
    ctx->event.message_type.regular_call.index.funcs.encode = NULL;
    ctx->event.message_type.regular_call.index.arg = NULL;
    ctx->event.message_type.regular_call.aux.funcs.encode = NULL;
    ctx->event.message_type.regular_call.aux.arg = NULL;
    ctx->event.message_type.regular_call.data.funcs.encode = NULL;
    ctx->event.message_type.regular_call.data.arg = NULL;
    
    ctx->encoded_size = 0;
}

void protobuf_finish(protobuf_context_t* ctx) {
    pb_ostream_t stream = pb_ostream_from_buffer(ctx->buffer, sizeof(ctx->buffer));
    if (pb_encode(&stream, HookEvent_fields, &ctx->event)) {
        ctx->encoded_size = stream.bytes_written;
    } else {
        ctx->encoded_size = 0;
    }
}

int protobuf_append_string(protobuf_context_t* ctx, const char* name, const char* value) {
    if (!value) return 0;
    
    if (ctx->event.which_message_type == HookEvent_str_tag) {
        StrMessage* str_msg = &ctx->event.message_type.str;
        
        if (strcmp(name, "name") == 0) {
            str_msg->name.funcs.encode = encode_string_callback;
            str_msg->name.arg = (void*)value;
        } else if (strcmp(name, "type") == 0) {
            str_msg->type.funcs.encode = encode_string_callback;
            str_msg->type.arg = (void*)value;
        } else if (strcmp(name, "category") == 0) {
            str_msg->category.funcs.encode = encode_string_callback;
            str_msg->category.arg = (void*)value;
        } else if (strcmp(name, "api_name") == 0) {
            str_msg->api_name.funcs.encode = encode_string_callback;
            str_msg->api_name.arg = (void*)value;
        }
    }
    
    return 1;
}

int protobuf_append_int(protobuf_context_t* ctx, const char* name, int32_t value) {
    if (ctx->event.which_message_type == HookEvent_regular_call_tag) {
        RegularCall* call = &ctx->event.message_type.regular_call;
        
        if (strcmp(name, "I") == 0 || strcmp(name, "i") == 0) {
            call->i = value;
        } else if (strcmp(name, "T") == 0 || strcmp(name, "t") == 0) {
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
        
        if (strcmp(name, "t") == 0) {
            call->t = (int32_t)value;  // Cast to int32 to match schema
        } else if (strcmp(name, "R") == 0) {
            call->r = (uint64_t)value;
        } else if (strcmp(name, "P") == 0) {
            call->p = (uint64_t)value;
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
    // No dynamic allocation in this version
}