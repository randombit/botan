/*
* GMP Wrapper
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/gmp_wrap.h>

#define GNU_MP_VERSION_CODE_FOR(a,b,c) ((a << 16) | (b << 8) | (c))

#define GNU_MP_VERSION_CODE \
   GNU_MP_VERSION_CODE_FOR(__GNU_MP_VERSION, __GNU_MP_VERSION_MINOR, \
                           __GNU_MP_VERSION_PATCHLEVEL)

#if GNU_MP_VERSION_CODE < GNU_MP_VERSION_CODE_FOR(4,1,0)
  #error Your GNU MP install is too old, upgrade to 4.1 or later
#endif

namespace Botan {

/*
* GMP_MPZ Constructor
*/
GMP_MPZ::GMP_MPZ(const BigInt& in)
   {
   mpz_init(value);
   if(in != 0)
      mpz_import(value, in.sig_words(), -1, sizeof(word), 0, 0, in.data());
   }

/*
* GMP_MPZ Constructor
*/
GMP_MPZ::GMP_MPZ(const byte in[], size_t length)
   {
   mpz_init(value);
   mpz_import(value, length, 1, 1, 0, 0, in);
   }

/*
* GMP_MPZ Copy Constructor
*/
GMP_MPZ::GMP_MPZ(const GMP_MPZ& other)
   {
   mpz_init_set(value, other.value);
   }

/*
* GMP_MPZ Destructor
*/
GMP_MPZ::~GMP_MPZ()
   {
   mpz_clear(value);
   }

/*
* GMP_MPZ Assignment Operator
*/
GMP_MPZ& GMP_MPZ::operator=(const GMP_MPZ& other)
   {
   mpz_set(value, other.value);
   return (*this);
   }

/*
* Export the mpz_t as a bytestring
*/
void GMP_MPZ::encode(byte out[], size_t length) const
   {
   size_t dummy = 0;
   mpz_export(out + (length - bytes()), &dummy, 1, 1, 0, 0, value);
   }

/*
* Return the number of significant bytes
*/
size_t GMP_MPZ::bytes() const
   {
   return ((mpz_sizeinbase(value, 2) + 7) / 8);
   }

/*
* GMP to BigInt Conversions
*/
BigInt GMP_MPZ::to_bigint() const
   {
   BigInt out(BigInt::Positive, (bytes() + sizeof(word) - 1) / sizeof(word));
   size_t dummy = 0;
   mpz_export(out.get_reg(), &dummy, -1, sizeof(word), 0, 0, value);

   if(mpz_sgn(value) < 0)
      out.flip_sign();

   return out;
   }

}
