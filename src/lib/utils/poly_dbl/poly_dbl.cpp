/*
* (C) 2017,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/poly_dbl.h>
#include <botan/loadstor.h>
#include <botan/exceptn.h>

namespace Botan {

namespace {

/*
* The minimum weight irreducible binary polynomial of size n
*
* See http://www.hpl.hp.com/techreports/98/HPL-98-135.pdf
*/
enum class MinWeightPolynomial : uint64_t {
   P64   = 0x1B,
   P128  = 0x87,
   P192  = 0x87,
   P256  = 0x425,
   P512  = 0x125,
   P1024 = 0x80043,
};

template<size_t LIMBS, MinWeightPolynomial P>
void poly_double(uint8_t out[], const uint8_t in[])
   {
   uint64_t W[LIMBS];
   load_be(W, in, LIMBS);

   const uint64_t POLY = static_cast<uint64_t>(P);

   const uint64_t carry = POLY * (W[0] >> 63);

   BOTAN_IF_CONSTEXPR(LIMBS > 0)
      {
      for(size_t i = 0; i != LIMBS - 1; ++i)
         W[i] = (W[i] << 1) ^ (W[i+1] >> 63);
      }

   W[LIMBS-1] = (W[LIMBS-1] << 1) ^ carry;

   copy_out_be(out, LIMBS*8, W);
   }

template<size_t LIMBS, MinWeightPolynomial P>
void poly_double_le(uint8_t out[], const uint8_t in[])
   {
   uint64_t W[LIMBS];
   load_le(W, in, LIMBS);

   const uint64_t POLY = static_cast<uint64_t>(P);

   const uint64_t carry = POLY * (W[LIMBS-1] >> 63);

   BOTAN_IF_CONSTEXPR(LIMBS > 0)
      {
      for(size_t i = 0; i != LIMBS - 1; ++i)
         W[LIMBS-1-i] = (W[LIMBS-1-i] << 1) ^ (W[LIMBS-2-i] >> 63);
      }

   W[0] = (W[0] << 1) ^ carry;

   copy_out_le(out, LIMBS*8, W);
   }

}

void poly_double_n(uint8_t out[], const uint8_t in[], size_t n)
   {
   switch(n)
      {
      case 8:
         return poly_double<1, MinWeightPolynomial::P64>(out, in);
      case 16:
         return poly_double<2, MinWeightPolynomial::P128>(out, in);
      case 24:
         return poly_double<3, MinWeightPolynomial::P192>(out, in);
      case 32:
         return poly_double<4, MinWeightPolynomial::P256>(out, in);
      case 64:
         return poly_double<8, MinWeightPolynomial::P512>(out, in);
      case 128:
         return poly_double<16, MinWeightPolynomial::P1024>(out, in);
      default:
         throw Invalid_Argument("Unsupported size for poly_double_n");
      }
   }

void poly_double_n_le(uint8_t out[], const uint8_t in[], size_t n)
   {
   switch(n)
      {
      case 8:
         return poly_double_le<1, MinWeightPolynomial::P64>(out, in);
      case 16:
         return poly_double_le<2, MinWeightPolynomial::P128>(out, in);
      case 24:
         return poly_double_le<3, MinWeightPolynomial::P192>(out, in);
      case 32:
         return poly_double_le<4, MinWeightPolynomial::P256>(out, in);
      case 64:
         return poly_double_le<8, MinWeightPolynomial::P512>(out, in);
      case 128:
         return poly_double_le<16, MinWeightPolynomial::P1024>(out, in);
      default:
         throw Invalid_Argument("Unsupported size for poly_double_n_le");
      }
   }

}
