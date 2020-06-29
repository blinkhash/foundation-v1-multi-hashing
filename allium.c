#include "Lyra2.h"

#include "blake2s.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "sha3/sph_blake.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_luffa.h"

#define CL_N    "\x1B[0m"
#define CL_CYN  "\x1B[36m"

#define printpfx(n,h) \
	printf("%s%11s%s: %s\n", CL_CYN, n, CL_N, format_hash(s, (uint8_t*) h))

static char* format_hash(char* buf, uint8_t *hash)
{
	int len = 0;
	for (int i=0; i < 32; i += 4) {
		len += sprintf(buf+len, "%02x%02x%02x%02x ",
			hash[i], hash[i+1], hash[i+2], hash[i+3]);
	}
	return buf;
}

void allium_hash(const char* input, char* state)
{
    uint32_t hashA[8], hashB[8];

    sph_blake256_context     ctx_blake;
    sph_keccak256_context    ctx_keccak;
    sph_skein256_context     ctx_skein;
    sph_groestl256_context   ctx_groestl;
    sph_cubehash256_context  ctx_cube;

    sph_blake256_init(&ctx_blake);
    sph_blake256(&ctx_blake, input, 80);
    sph_blake256_close(&ctx_blake, hashA);

    sph_keccak256_init(&ctx_keccak);
    sph_keccak256(&ctx_keccak, hashA, 32);
    sph_keccak256_close(&ctx_keccak, hashB);

    LYRA2(hashA, 32, hashB, 32, hashB, 32, 1, 8, 8);

    sph_cubehash256_init(&ctx_cube);
    sph_cubehash256(&ctx_cube, hashA, 32);
    sph_cubehash256_close(&ctx_cube, hashB);

    LYRA2(hashA, 32, hashB, 32, hashB, 32, 1, 8, 8);

    sph_skein256_init(&ctx_skein);
    sph_skein256(&ctx_skein, hashA, 32);
    sph_skein256_close(&ctx_skein, hashB);

    sph_groestl256_init(&ctx_groestl);
    sph_groestl256(&ctx_groestl, hashB, 32);
    sph_groestl256_close(&ctx_groestl, hashA);

    memcpy(state, hashA, 32);
}
