#include "sha512256d.h"

#include <stdlib.h>
#include <stdint.h>

#include "../common/sha3/sph_sha2.h"

void sha512256d_hash(const char* input, char* output)
{

	sph_sha512_context ctx;
	sph_sha512_256_init(&ctx);
	sph_sha512(&ctx, input, 80);
	uint32_t hash1[16];
	sph_sha512_close(&ctx, hash1);

	uint32_t hash2[16];
	sph_sha512_256_init(&ctx);
	sph_sha512(&ctx, hash1, 32);
	sph_sha512_close(&ctx, hash2);

	memcpy(output, hash2, 32);

}
