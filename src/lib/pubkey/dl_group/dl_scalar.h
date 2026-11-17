/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DL_SCALAR_H_
#define BOTAN_DL_SCALAR_H_

#include <botan/bigint.h>
#include <botan/concepts.h>
#include <botan/internal/monty.h>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace Botan {

class DL_Group;
class DL_Group_Data;
class RandomNumberGenerator;

/**
* An integer modulo the prime order q of a DL group
*
* This requires that the group has a known q of at most 256 bits.
*
* The value is stored in Montgomery form with a fixed length based on the
* size of q. All operations are constant time unless named _vartime.
*
* TODO(DSA) remove this once DSA is removed
*/
class BOTAN_TEST_API DL_Scalar final {
   public:
      /**
      * Throws Invalid_Argument unless 0 <= x < q
      */
      static DL_Scalar from_bigint(const DL_Group& group, const BigInt& x);

      /**
      * Return a uniformly random integer in [1,q)
      */
      static DL_Scalar random(const DL_Group& group, RandomNumberGenerator& rng);

      /**
      * Decode a big-endian integer of exactly q_bytes length
      *
      * Returns nullopt if the length is wrong or if the integer is not less than q
      */
      static std::optional<DL_Scalar> deserialize(const DL_Group& group, std::span<const uint8_t> bytes);

      /**
      * Convert the bytes to an integer, truncate to the leftmost q_bits bits,
      * then reduce modulo q
      */
      static DL_Scalar from_bytes_with_trunc(const DL_Group& group, std::span<const uint8_t> bytes);

      /**
      * Return (g^k mod p) mod q
      */
      static DL_Scalar g_pow_mod_q(const DL_Scalar& k);

      /**
      * Return (g^a * y^b mod p) mod q
      *
      * This takes time dependent on all inputs, so should only be used with
      * public values.
      *
      * @param a the exponent of g
      * @param y an integer in [0,p)
      * @param b the exponent of y
      */
      static DL_Scalar multi_exp_mod_q_vartime(const DL_Scalar& a, const BigInt& y, const DL_Scalar& b);

      DL_Scalar mul(const DL_Scalar& x) const;

      DL_Scalar add(const DL_Scalar& x) const;

      DL_Scalar square() const;

      /**
      * Return the multiplicative inverse
      *
      * Throws Invalid_Argument if this scalar is zero
      */
      DL_Scalar invert() const;

      bool is_zero() const;

      bool is_eq(const DL_Scalar& x) const;

      friend DL_Scalar operator*(const DL_Scalar& x, const DL_Scalar& y) { return x.mul(y); }

      friend DL_Scalar operator+(const DL_Scalar& x, const DL_Scalar& y) { return x.add(y); }

      friend bool operator==(const DL_Scalar& x, const DL_Scalar& y) { return x.is_eq(y); }

      /**
      * Return the length of the fixed length encoding, which is the byte
      * length of q
      */
      size_t bytes() const;

      /**
      * Write the fixed length big-endian encoding of this scalar
      *
      * The output span must be exactly bytes() long
      */
      void serialize_to(std::span<uint8_t> out) const;

      template <concepts::resizable_byte_buffer T = std::vector<uint8_t>>
      T serialize() const {
         T s(this->bytes());
         this->serialize_to(s);
         return s;
      }

      BigInt to_bigint() const;

      void _const_time_poison() const { m_v._const_time_poison(); }

      void _const_time_unpoison() const { m_v._const_time_unpoison(); }

   private:
      DL_Scalar(std::shared_ptr<const DL_Group_Data> group, Montgomery_Int v);

      void check_same_group(const DL_Scalar& other) const;

      std::shared_ptr<const DL_Group_Data> m_group;
      Montgomery_Int m_v;
};

}  // namespace Botan

#endif
