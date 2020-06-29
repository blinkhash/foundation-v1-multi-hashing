#ifndef GOST_H
#define GOST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void gost_hash(const char* input, char* output, uint8_t len);

#ifdef __cplusplus
}
#endif

#endif
