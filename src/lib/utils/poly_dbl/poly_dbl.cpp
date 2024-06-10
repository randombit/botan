/*
* (C) 2017,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/poly_dbl.h>

#include <botan/exceptn.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/loadstor.h>

namespace Botan {

namespace {

/*
* The minimum weight irreducible binary polynomial of size n
*
* See "Table of Low-Weight Binary Irreducible Polynomials"
* by Gadiel Seroussi, HP Labs Tech Report HPL-98-135
* http://www.hpl.hp.com/techreports/98/HPL-98-135.pdf
*/
enum class MinWeightPolynomial : uint32_t {
   P64 = 0x1B,
   P128 = 0x87,
   P192 = 0x87,
   P256 = 0x425,
   P512 = 0x125,
   P1024 = 0x80043,
};

/**
* If the top bit of c is set, returns the carry (the polynomial)
*
* Otherwise returns zero.
*/
template <MinWeightPolynomial P>
inline uint64_t return_carry(uint64_t c) {
   return CT::Mask<uint64_t>::expand_top_bit(c).if_set_return(static_cast<uint64_t>(P));
}

template <size_t LIMBS, MinWeightPolynomial P>
void poly_double(uint8_t out[], const uint8_t in[]) {
   uint64_t W[LIMBS];
   load_be(W, in, LIMBS);

   const uint64_t carry = return_carry<P>(W[0]);

   if constexpr(LIMBS > 0) {
      for(size_t i = 0; i != LIMBS - 1; ++i) {
         W[i] = (W[i] << 1) ^ (W[i + 1] >> 63);
      }
   }

   W[LIMBS - 1] = (W[LIMBS - 1] << 1) ^ carry;

   copy_out_be(std::span(out, LIMBS * 8), W);
}

template <size_t LIMBS, MinWeightPolynomial P>
void poly_double_le(uint8_t out[], const uint8_t in[]) {
   uint64_t W[LIMBS];
   load_le(W, in, LIMBS);

   const uint64_t carry = return_carry<P>(W[LIMBS - 1]);

   if constexpr(LIMBS > 0) {
      for(size_t i = 0; i != LIMBS - 1; ++i) {
         W[LIMBS - 1 - i] = (W[LIMBS - 1 - i] << 1) ^ (W[LIMBS - 2 - i] >> 63);
      }
   }

   W[0] = (W[0] << 1) ^ carry;

   copy_out_le(std::span(out, LIMBS * 8), W);
}

}  // namespace

void poly_double_n(uint8_t out[], const uint8_t in[], size_t n) {
   switch(n) {
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

void poly_double_n_le(uint8_t out[], const uint8_t in[], size_t n) {
   switch(n) {
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

void xts_update_tweak_block(uint8_t tweak[], size_t BS, size_t blocks_in_tweak) {
   if(BS == 16) {
      constexpr size_t LIMBS = 2;

      uint64_t W[LIMBS];
      load_le(W, &tweak[0], LIMBS);

      for(size_t i = 1; i < blocks_in_tweak; ++i) {
         const uint64_t carry = return_carry<MinWeightPolynomial::P128>(W[1]);
         W[1] = (W[1] << 1) ^ (W[0] >> 63);
         W[0] = (W[0] << 1) ^ carry;
         copy_out_le(std::span(&tweak[i * BS], 2 * 8), W);
      }
   } else {
      for(size_t i = 1; i < blocks_in_tweak; ++i) {
         const uint8_t* prev = &tweak[(i - 1) * BS];
         uint8_t* cur = &tweak[i * BS];
         poly_double_n_le(cur, prev, BS);
      }
   }
}

}  // namespace Botan
