#ifndef PROTOBUF_WRAPPER_H
#define PROTOBUF_WRAPPER_H

#include "schema.pb.h"
#include "nanopb/pb_encode.h"
#include "nanopb/pb_decode.h"
#include <stddef.h>
#include <stdint.h>

typedef struct {
    const uint8_t *ptr;
    size_t len;
} pb_binary_t;

// Simple context structure
typedef struct {
    HookEvent event;
    uint8_t buffer[65536];
    size_t encoded_size;
    
    char string_scratch[32768];
    size_t scratch_offset;
    
    pb_binary_t bin_args;
    pb_binary_t bin_data;
    pb_binary_t bin_c;
    pb_binary_t bin_index;
    pb_binary_t bin_aux;
} protobuf_context_t;

// Initialization
void protobuf_init(protobuf_context_t* ctx, int message_type);
void protobuf_finish(protobuf_context_t* ctx);

// Field appending - simplified for callback-based fields.
// `length` is the source unit count, or -1 when the input is NUL-terminated;
// implementations must honour it and never strlen()/lstrlenW() the raw input.
int protobuf_append_string(protobuf_context_t* ctx, const char* name, const char* value, int length);
int protobuf_append_wstring(protobuf_context_t* ctx, const char* name, const wchar_t* value, int length);
int protobuf_append_int(protobuf_context_t* ctx, const char* name, int32_t value);
int protobuf_append_long(protobuf_context_t* ctx, const char* name, int64_t value);
int protobuf_append_binary(protobuf_context_t* ctx, const char* name, const void* buf, size_t len);

// Finalization
size_t protobuf_size(protobuf_context_t* ctx);
const uint8_t* protobuf_data(protobuf_context_t* ctx);
void protobuf_destroy(protobuf_context_t* ctx);

#endif
