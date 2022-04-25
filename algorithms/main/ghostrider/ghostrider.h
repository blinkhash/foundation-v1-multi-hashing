#ifndef GHOSTRIDER_H
#define GHOSTRIDER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void ghostrider_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
