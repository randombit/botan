/*
* CTR_DRBG without the derivation function
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CTR_DRBG_NODF_H_
#define BOTAN_CTR_DRBG_NODF_H_

#include <botan/ctr_drbg.h>

namespace Botan {

/**
* Creates CTR_DRBG instances which do not use the derivation function
*
* In this mode no conditioning is performed. Each input is padded with zeros
* to the seed length (the cipher key length plus 16 bytes) and used directly
* as the new key and counter; longer inputs are rejected. Combining the
* entropy input with a personalization string or additional input using XOR
* is left to the caller.
*
* This exists only to reproduce test vectors which use this mode, such as the
* NIST PQC KATs which use CTR_DRBG(AES-256) seeded with 48 bytes. It is not
* suitable for seeding from entropy sources and is not part of the public API.
*/
class BOTAN_TEST_API CTR_DRBG_Without_DF final {
   public:
      static std::unique_ptr<CTR_DRBG> create(std::unique_ptr<BlockCipher> cipher);

      static std::unique_ptr<CTR_DRBG> create(std::string_view cipher);
};

}  // namespace Botan

#endif
