#include "gost.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "sha3/sph_gost.h"

void gost_hash(const char* input, char* output, uint8_t len)
{
    sph_gost512_context ctx_gost;
    sph_gost512_init(&ctx_gost);
    sph_gost512(&ctx_gost, input, len);
    sph_gost512_close(&ctx_gost, output);
}

