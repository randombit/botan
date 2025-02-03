/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EC_SCALAR_H_
#define BOTAN_EC_SCALAR_H_

#include <botan/concepts.h>
#include <botan/types.h>
#include <optional>
#include <span>
#include <vector>

namespace Botan {

class BigInt;
class RandomNumberGenerator;
class EC_Group;
class EC_Group_Data;
class EC_Scalar_Data;

/**
* Represents an integer modulo the prime group order of an elliptic curve
*/
class BOTAN_UNSTABLE_API EC_Scalar final {
   public:
      /**
      * Deserialize a scalar
      *
      * The span must be exactly bytes() long; this function does not accept
      * either short inputs (eg [1] to encode the integer 1) or inputs with
      * excess leading zero bytes.
      *
      * Returns nullopt if the length is incorrect or if the integer is not
      * within the range [0,n) where n is the group order.
      */
      static std::optional<EC_Scalar> deserialize(const EC_Group& group, std::span<const uint8_t> bytes);

      /**
      * Convert a bytestring to an EC_Scalar
      *
      * This uses the truncation rules from ECDSA
      */
      static EC_Scalar from_bytes_with_trunc(const EC_Group& group, std::span<const uint8_t> bytes);

      /**
      * Convert a bytestring to an EC_Scalar
      *
      * This reduces the bytes modulo the group order. The input can be at most
      * 2*bytes() long
      */
      static EC_Scalar from_bytes_mod_order(const EC_Group& group, std::span<const uint8_t> bytes);

      /**
      * Convert a bytestring to an EC_Scalar
      *
      * This is similar to deserialize but instead of returning nullopt if the input
      * is invalid, it will throw an exception.
      */
      BOTAN_DEPRECATED("Use EC_Scalar::deserialize") EC_Scalar(const EC_Group& group, std::span<const uint8_t> bytes);

      /**
      * Deserialize a pair of scalars
      *
      * Returns nullopt if the length is not 2*bytes(), or if either scalar is
      * out of range or zero
      */
      static std::optional<std::pair<EC_Scalar, EC_Scalar>> deserialize_pair(const EC_Group& group,
                                                                             std::span<const uint8_t> bytes);

      /**
      * Return a new random scalar value
      */
      static EC_Scalar random(const EC_Group& group, RandomNumberGenerator& rng);

      /**
      * Return the scalar value 1
      */
      static EC_Scalar one(const EC_Group& group);

      /**
      * Convert from the argument BigInt to a EC_Scalar
      *
      * Throws an exception if the provided bn is negative or too large
      */
      static EC_Scalar from_bigint(const EC_Group& group, const BigInt& bn);

      /**
      * Compute the elliptic curve scalar multiplication (g*k) where g is the
      * standard base point on the curve. Then extract the x coordinate of
      * the resulting point, and reduce it modulo the group order.
      *
      * Workspace argument is transitional
      */
      static EC_Scalar gk_x_mod_order(const EC_Scalar& scalar, RandomNumberGenerator& rng, std::vector<BigInt>& ws);

      /**
      * Return the byte size of this scalar
      */
      size_t bytes() const;

      /**
      * Write the fixed length serialization to bytes
      *
      * The provided span must be exactly bytes() long
      */
      void serialize_to(std::span<uint8_t> bytes) const;

      /**
      * Return the bytes of the encoded scalar in a container
      */
      template <concepts::resizable_byte_buffer T = std::vector<uint8_t>>
      T serialize() const {
         T s(this->bytes());
         this->serialize_to(s);
         return s;
      }

      /**
      * Write the fixed length serialization to bytes
      *
      * The provided span must be exactly 2*bytes() long
      */
      static void serialize_pair_to(std::span<uint8_t> bytes, const EC_Scalar& r, const EC_Scalar& s);

      /**
      * Return the bytes of the encoded scalar in a container
      */
      template <concepts::resizable_byte_buffer T = std::vector<uint8_t>>
      static T serialize_pair(const EC_Scalar& r, const EC_Scalar& s) {
         T bytes(r.bytes() + s.bytes());
         serialize_pair_to(bytes, r, s);
         return bytes;
      }

      /**
      * Return true if this EC_Scalar is zero
      */
      bool is_zero() const;

      /**
      * Return true if this EC_Scalar is not zero
      */
      bool is_nonzero() const { return !is_zero(); }

      /**
      * Constant time modular inversion
      *
      * Return the modular inverse of this EC_Scalar
      *
      * If *this is zero, then invert() returns zero
      */
      EC_Scalar invert() const;

      /**
      * Variable time modular inversion
      *
      * Return the modular inverse of this EC_Scalar
      *
      * If *this is zero, then invert_vartime() returns zero
      */
      EC_Scalar invert_vartime() const;

      /**
      * Return the additive inverse of *this
      */
      EC_Scalar negate() const;

      /**
      * Scalar addition (modulo group order)
      */
      EC_Scalar add(const EC_Scalar& x) const;

      /**
      * Scalar subtraction (modulo group order)
      */
      EC_Scalar sub(const EC_Scalar& x) const;

      /**
      * Scalar multiplication (modulo group order)
      */
      EC_Scalar mul(const EC_Scalar& x) const;

      /**
      * Assign a scalar
      */
      void assign(const EC_Scalar& x);

      /**
      * Set *this to its own square modulo the group order
      */
      void square_self();

      /**
      * Test for equality
      */
      bool is_eq(const EC_Scalar& x) const;

      /**
      * Convert *this to a BigInt
      */
      BigInt to_bigint() const;

      friend EC_Scalar operator+(const EC_Scalar& x, const EC_Scalar& y) { return x.add(y); }

      friend EC_Scalar operator-(const EC_Scalar& x, const EC_Scalar& y) { return x.sub(y); }

      friend EC_Scalar operator*(const EC_Scalar& x, const EC_Scalar& y) { return x.mul(y); }

      friend bool operator==(const EC_Scalar& x, const EC_Scalar& y) { return x.is_eq(y); }

      EC_Scalar(const EC_Scalar& other);
      EC_Scalar(EC_Scalar&& other) noexcept;

      EC_Scalar& operator=(const EC_Scalar& other);
      EC_Scalar& operator=(EC_Scalar&& other) noexcept;

      ~EC_Scalar();

      const EC_Scalar_Data& _inner() const { return inner(); }

      static EC_Scalar _from_inner(std::unique_ptr<EC_Scalar_Data> inner);

   private:
      friend class EC_AffinePoint;

      EC_Scalar(std::unique_ptr<EC_Scalar_Data> scalar);

      const EC_Scalar_Data& inner() const { return *m_scalar; }

      std::unique_ptr<EC_Scalar_Data> m_scalar;
};

}  // namespace Botan

#endif
