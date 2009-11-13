/*
* Format Preserving Encryption
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_FORMAT_PRESERVING_ENCRYPTION_H__
#define BOTAN_FORMAT_PRESERVING_ENCRYPTION_H__

#include <botan/bigint.h>
#include <botan/symkey.h>

namespace Botan {

BigInt fpe_encrypt(const BigInt& n, const BigInt& X,
                   const SymmetricKey& key,
                   const MemoryRegion<byte>& tweak);

BigInt fpe_decrypt(const BigInt& n, const BigInt& X,
                   const SymmetricKey& key,
                   const MemoryRegion<byte>& tweak);

}

#endif
