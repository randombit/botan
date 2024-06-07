/*
* X448 Internal
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#ifndef BOTAN_X448_INTERNAL_H_
#define BOTAN_X448_INTERNAL_H_

#include <botan/secmem.h>
#include <botan/strong_type.h>

namespace Botan {

constexpr size_t X448_LEN = 56;

using Point448 = Strong<std::array<uint8_t, X448_LEN>, struct Point448_>;

// Note that we do not use the scalar of x448_scalar.h since the x448 algorithm
// requires a scalar that is even. When reducing (modulo the group order) the scalar using
// this class, the computation becomes invalid. Since we do not need to reduce, we
// simply work on bytes for x448 */
using ScalarX448 = Strong<std::array<uint8_t, X448_LEN>, struct ScalarX448_>;

/**
 * @brief Multiply a scalar with the standard group element (5)
 *
 * @param k scalar
 * @return encoded point
 */
Point448 x448_basepoint(const ScalarX448& k);

/**
 * @brief Multiply a scalar @p k with a point @p u
 *
 * @param k scalar
 * @param u point on curve
 * @return k * u
 */
Point448 x448(const ScalarX448& k, const Point448& u);

/// Encode a point to a 56 byte vector. RFC 7748 Section 5 (encodeUCoordinate)
secure_vector<uint8_t> encode_point(const Point448& p);

/// Decode a point from a byte array. RFC 7748 Section 5 (decodeUCoordinate)
Point448 decode_point(std::span<const uint8_t> p_bytes);

/// Decode a scalar from a byte array. RFC 7748 Section 5 (decodeScalar448)
ScalarX448 decode_scalar(std::span<const uint8_t> scalar_bytes);

}  // namespace Botan

#endif  // BOTAN_X448_INTERNAL_H_
