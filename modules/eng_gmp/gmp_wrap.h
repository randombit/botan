/*************************************************
* GMP MPZ Wrapper Header File                    *
* (C) 1999-2008 The Botan Project                *
*************************************************/

#ifndef BOTAN_EXT_GMP_MPZ_WRAP_H__
#define BOTAN_EXT_GMP_MPZ_WRAP_H__

#include <botan/bigint.h>
#include <gmp.h>

namespace Botan {

/*************************************************
* Lightweight GMP mpz_t Wrapper                  *
*************************************************/
class GMP_MPZ
   {
   public:
      mpz_t value;

      BigInt to_bigint() const;
      void encode(byte[], u32bit) const;
      u32bit bytes() const;

      GMP_MPZ& operator=(const GMP_MPZ&);

      GMP_MPZ(const GMP_MPZ&);
      GMP_MPZ(const BigInt& = 0);
      GMP_MPZ(const byte[], u32bit);
      ~GMP_MPZ();
   };

}

#endif
