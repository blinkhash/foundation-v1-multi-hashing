#ifndef SKUNK_H
#define SKUNK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define _ALIGN(x) __attribute__ ((aligned(x)))
extern void debuglog_hex(void *data, int len);

void skunk_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
