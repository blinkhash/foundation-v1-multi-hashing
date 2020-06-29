#ifndef SCRYPT_H
#define SCRYPT_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

void m7_hash(const char* input, char* output);
void m7m_hash(const char* input, char* output);

#ifdef __cplusplus
}
#endif

#endif
