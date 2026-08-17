#ifndef LOG_SERIALIZER_H
#define LOG_SERIALIZER_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    LOG_FORMAT_BSON = 0,
    LOG_FORMAT_PROTOBUF = 1
} log_format_t;

typedef struct _log_serializer_t {
    void (*init)(void);
    void (*append_int)(const char *name, int32_t val);
    void (*append_long)(const char *name, int64_t val);
    void (*append_string)(const char *name, const char *val);
    void (*append_wstring)(const char *name, const wchar_t *val);
    void (*append_binary)(const char *name, const void *buf, size_t len);
    void (*append_finish)(void);
    void (*append_start_array)(const char *name);
    void (*append_finish_array)(void);
    const uint8_t* (*get_data)(void);
    size_t (*get_size)(void);
    void (*destroy)(void);
} log_serializer_t;

extern log_serializer_t g_bson_serializer;
extern log_serializer_t g_protobuf_serializer;

// g_active_serializer is a macro defined in log.c for thread-safe access

#endif
