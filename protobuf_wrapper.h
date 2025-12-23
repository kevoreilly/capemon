#ifndef PROTOBUF_WRAPPER_H
#define PROTOBUF_WRAPPER_H

#include "schema.pb.h"
#include "nanopb/pb_encode.h"
#include "nanopb/pb_decode.h"
#include <stddef.h>
#include <stdint.h>

// Simple context structure
typedef struct {
    HookEvent event;
    uint8_t buffer[4096];
    size_t encoded_size;
} protobuf_context_t;

// Initialization
void protobuf_init(protobuf_context_t* ctx);
void protobuf_finish(protobuf_context_t* ctx);

// Field appending - simplified for callback-based fields
int protobuf_append_string(protobuf_context_t* ctx, const char* name, const char* value);
int protobuf_append_int(protobuf_context_t* ctx, const char* name, int32_t value);
int protobuf_append_long(protobuf_context_t* ctx, const char* name, int64_t value);

// Finalization
size_t protobuf_size(protobuf_context_t* ctx);
const uint8_t* protobuf_data(protobuf_context_t* ctx);
void protobuf_destroy(protobuf_context_t* ctx);

#endif