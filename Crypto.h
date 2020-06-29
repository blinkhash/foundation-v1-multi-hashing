#ifndef CRYPTO_H_
#define CRYPTO_H_

#include "Common.h"
#include "Util.h"
#include <string>
#include <vector>
#include <openssl/sha.h>

namespace Crypto
{
	BinaryData GOSTD(BinaryData data);
}

#endif
