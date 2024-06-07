/*
* X448 Gf Modulo 2^448 - 2^224 - 1
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#ifndef BOTAN_CURVE_448_GF_H_
#define BOTAN_CURVE_448_GF_H_

#include <botan/mem_ops.h>
#include <botan/types.h>
#include <botan/internal/bit_ops.h>

#include <array>
#include <span>

namespace Botan {

constexpr size_t BYTES_448 = ceil_tobytes(448);
/* uint64_t words to store a 448 bit value */
constexpr size_t WORDS_448 = 7;

/**
 * This class represents a GF element in the field GF(2^448 - 2^224 - 1). Computations are
 * performed using optimized operations as defined in the paper:
 * "Reduction Modulo 2^448 - 2^224 - 1" by Kaushik Nath and Palash Sarkar
 * (https://eprint.iacr.org/2019/1304).
 *
 * The representation of the field element is a 448-bit uint, stored in little-endian order
 * as 7*64bit words. Note that the internal representation is not necessarily canonical, i.e.
 * the value might be larger than the prime modulus. When calling the to_bytes() method, the
 * canonical representation is returned.
 */
class Gf448Elem final {
   public:
      /**
       * @brief Construct a GF element from a 448-bit integer gives as 56 bytes @p x in
       * little-endian order.
       */
      Gf448Elem(std::span<const uint8_t, BYTES_448> x);

      /**
       * @brief Construct a GF element from a 448-bit integer gives as 7 uint64_t words @p x in
       * little-endian order.
       */
      Gf448Elem(std::span<const uint64_t, WORDS_448> data) { copy_mem(m_x, data); }

      /**
       * @brief Construct a GF element by passing the least significant 64 bits as a word.
       * All other become zero.
       */
      Gf448Elem(uint64_t least_sig_word);

      /**
       * @brief Store the canonical representation of the GF element as 56 bytes in little-endian
       * order.
       *
       * @param out The 56 byte output buffer.
       */
      void to_bytes(std::span<uint8_t, BYTES_448> out) const;

      /**
       * @brief Return the canonical representation of the GF element as 56 bytes in little-endian
       * order.
       */
      std::array<uint8_t, BYTES_448> to_bytes() const;

      /**
       * @brief Swap this and other if b == true. Constant time for any b.
       */
      void ct_cond_swap(bool b, Gf448Elem& other);

      /**
       * @brief Set this to @p other if b is true. Constant time for any b.
       */
      void ct_cond_assign(bool b, const Gf448Elem& other);

      Gf448Elem operator+(const Gf448Elem& other) const;

      Gf448Elem operator-(const Gf448Elem& other) const;

      Gf448Elem operator-() const;

      Gf448Elem operator*(const Gf448Elem& other) const;

      Gf448Elem operator/(const Gf448Elem& other) const;

      bool operator==(const Gf448Elem& other) const;

      bool operator!=(const Gf448Elem& other) const = default;

      /**
       * @brief Return true iff this element is zero. Constant time.
       */
      bool is_zero() const;

      /**
       * @brief Return true iff this element is odd. Constant time.
       */
      bool is_odd() const;

      /**
       * @brief Accessor to the internal words of the GF element.
       *
       * Note that the internal representation is not necessarily canonical, i.e.
       * the value might be larger than the prime modulus.
       */
      std::span<uint64_t, WORDS_448> words() { return m_x; }

      /**
       * @brief Constant accessor to the internal words of the GF element.
       *
       * Note that the internal representation is not necessarily canonical, i.e.
       * the value might be larger than the prime modulus.
       */
      std::span<const uint64_t, WORDS_448> words() const { return m_x; }

      /**
       * @brief Given 56 bytes, checks that the (little endian) number from this
       * bytes is a valid GF element, i.e. is smaller than the prime modulus.
       */
      static bool bytes_are_canonical_representation(std::span<const uint8_t, BYTES_448> x);

   private:
      std::array<uint64_t, WORDS_448> m_x;
};

/**
 * @brief Computes elem^2. Faster than operator*.
 */
Gf448Elem square(const Gf448Elem& elem);

/**
 * @brief Compute the root of @p elem in the field.
 *
 * The root of a in GF(p) is computed as r = a^((p+1)/4) mod p.
 * Note that the root is not unique, i.e. r and p-r are both roots.
 *
 * @return GfPElem The root of this element.
 */
Gf448Elem root(const Gf448Elem& elem);

}  // namespace Botan

#endif  // BOTAN_CURVE_448_GF_H_
