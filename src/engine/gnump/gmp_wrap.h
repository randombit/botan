/*
* GMP MPZ Wrapper
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_GMP_MPZ_WRAP_H__
#define BOTAN_GMP_MPZ_WRAP_H__

#include <botan/bigint.h>
#include <gmp.h>

namespace Botan {

/**
* Lightweight GMP mpz_t wrapper. For internal use only.
*/
class GMP_MPZ
   {
   public:
      mpz_t value;

      BigInt to_bigint() const;
      void encode(byte[], size_t) const;
      size_t bytes() const;

      SecureVector<byte> to_bytes() const
         { return BigInt::encode(to_bigint()); }

      GMP_MPZ& operator=(const GMP_MPZ&);

      GMP_MPZ(const GMP_MPZ&);
      GMP_MPZ(const BigInt& = 0);
      GMP_MPZ(const byte[], size_t);
      ~GMP_MPZ();
   };

}

#endif
