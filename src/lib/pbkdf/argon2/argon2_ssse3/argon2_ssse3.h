/**
* (C) 2022 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ARGON2_SSSE3_H_
#define BOTAN_ARGON2_SSSE3_H_

#include <botan/types.h>

namespace Botan {

void blamka_ssse3(uint64_t T[128]);

}

#endif
