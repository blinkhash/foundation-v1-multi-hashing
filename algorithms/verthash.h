#ifndef VERTHASH_INCLUDED
#define VERTHASH_INCLUDED
#include <stdlib.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

int verthash(const char* input, char* output, uint32_t input_size);
int verthash_init(const char* dat_file_name, int createIfMissing);

#ifdef __cplusplus
}
#endif

#endif
