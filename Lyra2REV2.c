#include "Lyra2RE.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "Lyra2.h"

void lyra2rev2_hash(const char* input, char* output)
{

    uint32_t hashB[8];


	LYRA2((void*)hashB, 32, (const void*)input, 80, (const void*)input, 80, 2, 330, 256);


	memcpy(output, hashB, 32);
}


