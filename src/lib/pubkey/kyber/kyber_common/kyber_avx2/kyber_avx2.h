/*
 * Kyber/ML-KEM polynomial arithmetic using AVX2
 * (C) 2026 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_KYBER_AVX2_H_
#define BOTAN_KYBER_AVX2_H_

#include <botan/internal/kyber_constants.h>
#include <span>

namespace Botan::Kyber_AVX2 {

/**
 * AVX2 versions of the KyberPolyTraits operations of the same name.
 *
 * The polynomials use the standard coefficient order in memory, so the
 * results are interchangeable with the scalar implementations: ntt and
 * poly_pointwise_montgomery produce identical values, inverse_ntt values
 * that are congruent mod q and within (-q, q).
 */
BOTAN_TEST_API void ntt(std::span<int16_t, 256> p);

BOTAN_TEST_API void inverse_ntt(std::span<int16_t, 256> p);

BOTAN_TEST_API void poly_pointwise_montgomery(std::span<int16_t, 256> result,
                                              std::span<const int16_t, 256> lhs,
                                              std::span<const int16_t, 256> rhs);

}  // namespace Botan::Kyber_AVX2

#endif
