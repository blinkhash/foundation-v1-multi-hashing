#ifndef CRYPTO_H_
#define CRYPTO_H_

#include "common.h"
#include "util.h"
#include <string>
#include <vector>
#include <openssl/sha.h>

namespace Crypto
{
	BinaryData GOSTD(BinaryData data);
}

#endif
