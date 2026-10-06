/*
* Ed25519 scalar
* (C) 2017 Ribose Inc
*     2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ED25519_SCALAR_H_
#define BOTAN_ED25519_SCALAR_H_

#include <botan/types.h>
#include <array>
#include <optional>
#include <span>

namespace Botan {

/**
* An integer modulo the order of the Ed25519 group,
* l = 2^252 + 27742317777372353535851937790883648493
*
* Values are always fully reduced, and all operations aside from
* from_canonical_bytes are constant time.
*/
class BOTAN_TEST_API Ed25519_Scalar final {
   private:
      static constexpr size_t WORDS = 32 / sizeof(word);

   public:
      static constexpr size_t BYTES = 32;

      static Ed25519_Scalar zero() { return Ed25519_Scalar(std::array<word, WORDS>{}); }

      static Ed25519_Scalar one() { return Ed25519_Scalar(std::array<word, WORDS>{1}); }

      /**
      * Deserialize 32 little endian bytes, reducing modulo l
      */
      static Ed25519_Scalar from_bytes(std::span<const uint8_t, BYTES> b);

      /**
      * Deserialize 64 little endian bytes (eg a wide hash output),
      * reducing modulo l
      */
      static Ed25519_Scalar from_wide_bytes(std::span<const uint8_t, 2 * BYTES> b);

      /**
      * Deserialize 32 little endian bytes, returning nullopt unless the
      * value is already reduced
      */
      static std::optional<Ed25519_Scalar> from_canonical_bytes(std::span<const uint8_t, BYTES> b);

      /**
      * Serialize to 32 little endian bytes
      */
      void serialize_to(std::span<uint8_t, BYTES> b) const;

      std::array<uint8_t, BYTES> to_bytes() const {
         std::array<uint8_t, BYTES> b;  // NOLINT(*-member-init)
         serialize_to(b);
         return b;
      }

      Ed25519_Scalar operator+(const Ed25519_Scalar& other) const;

      Ed25519_Scalar operator*(const Ed25519_Scalar& other) const;

      Ed25519_Scalar operator-() const;

   private:
      explicit Ed25519_Scalar(const std::array<word, WORDS>& v) : m_val(v) {}

      std::array<word, WORDS> m_val;
};

}  // namespace Botan

#endif
