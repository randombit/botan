/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MP_MULX_H_
#define BOTAN_MP_MULX_H_

#include <botan/types.h>
#include <botan/internal/cpuid.h>

namespace Botan {

/*
* Multiplication and squaring using MULX and ADX, see gen_mp_mulx.py
*
* The output z must not overlap x or y
*/
void bigint_mulx_mul4(word z[8], const word x[4], const word y[4]);
void bigint_mulx_mul6(word z[12], const word x[6], const word y[6]);
void bigint_mulx_mul8(word z[16], const word x[8], const word y[8]);
void bigint_mulx_mul9(word z[18], const word x[9], const word y[9]);

void bigint_mulx_sqr4(word z[8], const word x[4]);
void bigint_mulx_sqr6(word z[12], const word x[6]);
void bigint_mulx_sqr8(word z[16], const word x[8]);
void bigint_mulx_sqr9(word z[18], const word x[9]);

// Below this many words, the dedicated fixed size reductions are faster
constexpr size_t MulxMontyMinWords = 9;

inline bool use_mulx_monty(size_t p_size) {
   return p_size >= MulxMontyMinWords && CPUID::has(CPUID::Feature::BMI, CPUID::Feature::ADX);
}

/**
* Fused Montgomery multiplication
*
* Computes z[0..N) = x*y*2^(-64*N) mod p for x, y < p. z may alias x or y.
* ws must hold at least N + 3 words.
*/
void bigint_mulx_monty_mul(word z[], const word x[], const word y[], const word p[], size_t N, word p_dash, word ws[]);

/**
* Montgomery squaring
*
* Computes z[0..N) = x*x*2^(-64*N) mod p for x < p. z may alias x.
* ws must hold at least 2N + 1 words.
*/
void bigint_mulx_monty_sqr(word z[], const word x[], const word p[], size_t N, word p_dash, word ws[]);

/**
* Squaring for any size: z[0..2N) = x^2, with z[2N] cleared
*
* The output z must not overlap x and must have 2N+1 words
*/
void bigint_mulx_sqr(word z[], const word x[], size_t N);

/**
* Montgomery reduction of a 2N word value z, which is destroyed
*
* Computes r[0..N) = z*2^(-64*N) mod p for z < p*2^(64*N). The buffer z must
* have 2N+1 words.
*/
void bigint_mulx_monty_redc(word r[], word z[], const word p[], size_t N, word p_dash);

}  // namespace Botan

#endif
