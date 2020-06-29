#include "crypto/odocrypt.h"
extern "C" {
#include "sha3/KeccakP-800-SnP.h"
#include <string.h>
}

void odo_hash(const char* input, char* output, uint32_t input_len, uint32_t key) {
    char cipher[KeccakP800_stateSizeInBytes] = {};

    memcpy(cipher, input, input_len);
    cipher[input_len] = 1;

    OdoCrypt(key).Encrypt(cipher, cipher);
    KeccakP800_Permute_12rounds(cipher);
    memcpy(output, cipher, 32);
}
