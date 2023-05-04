/*
* SHA-3
* (C) 2010,2016 Jack Lloyd
* (C) 2023 Falko Strenzke
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SHA3_H_
#define BOTAN_SHA3_H_

#include <botan/hash.h>
#include <botan/secmem.h>
#include <botan/internal/keccak_fips.h>
#include <string>

namespace Botan {

/**
* SHA-3
*/

class SHA_3 : public Keccak_FIPS
   {
   public:

      /**
      * @param output_bits the size of the hash output; must be one of
      *                    224, 256, 384, or 512
      */
      explicit SHA_3(size_t output_bits);
   };

/**
* SHA-3-224
*/
class SHA_3_224 final : public SHA_3
   {
   public:
      SHA_3_224() : SHA_3(224) {}
   };

/**
* SHA-3-256
*/
class SHA_3_256 final : public SHA_3
   {
   public:
      SHA_3_256() : SHA_3(256) {}
   };

/**
* SHA-3-384
*/
class SHA_3_384 final : public SHA_3
   {
   public:
      SHA_3_384() : SHA_3(384) {}
   };

/**
* SHA-3-512
*/
class SHA_3_512 final : public SHA_3
   {
   public:
      SHA_3_512() : SHA_3(512) {}
   };

}

#endif

