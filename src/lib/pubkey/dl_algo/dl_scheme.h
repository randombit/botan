/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DL_SCHEME_H_
#define BOTAN_DL_SCHEME_H_

#include <botan/bigint.h>
#include <botan/dl_group.h>
#include <botan/internal/dl_element.h>
#include <memory>
#include <span>
#include <string_view>

namespace Botan {

class AlgorithmIdentifier;
class RandomNumberGenerator;

class DL_PublicKey final {
   public:
      DL_PublicKey(const DL_Group& group, const BigInt& public_key);

      DL_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits, DL_Group_Format format);

      bool check_key(RandomNumberGenerator& rng, bool strong) const;

      const DL_Group& group() const { return m_group; }

      const BigInt& public_key() const { return m_public_key; }

      // Return the binary representation of the integer public key
      std::vector<uint8_t> public_key_as_bytes() const;

      const BigInt& get_int_field(std::string_view algo_name, std::string_view field) const;

      std::vector<uint8_t> DER_encode() const;

      size_t estimated_strength() const;

      size_t p_bits() const;

   private:
      const DL_Group m_group;
      const BigInt m_public_key;
};

class DL_PrivateKey final {
   public:
      DL_PrivateKey(const DL_Group& group, const BigInt& private_key);

      DL_PrivateKey(const DL_Group& group, RandomNumberGenerator& rng);

      DL_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits, DL_Group_Format format);

      bool check_key(RandomNumberGenerator& rng, bool strong) const;

      /**
      * Return a new shared_ptr of the associated public key
      */
      std::shared_ptr<DL_PublicKey> public_key() const;

      /**
      * Return the group this key operates in
      */
      const DL_Group& group() const { return m_group; }

      /**
      * Return the integer value of the private key
      */
      const BigInt& private_key() const { return m_private_key; }

      /**
      * Return a public upper bound on the bit length of the private key,
      * for use as the exponent length when exponentiating by it
      */
      size_t max_private_key_bits() const { return m_max_private_key_bits; }

      /**
      * DER encode the private key
      */
      secure_vector<uint8_t> DER_encode() const;

      /**
      * Return the raw serialization of the private key
      */
      secure_vector<uint8_t> raw_private_key_bits() const;

      const BigInt& get_int_field(std::string_view algo_name, std::string_view field) const;

   private:
      const DL_Group m_group;
      const BigInt m_private_key;
      const size_t m_max_private_key_bits;
      const BigInt m_public_key;
};

/**
* Computes b^x or b^-x mod p for a DL private key x
*
* The base is multiplied by a random blinding element e. For b^x the result is
* multiplied by e^-x. For b^-x the result is inverted and then multiplied by
* e^x, so the value which is inverted is blinded.
*
* Each call derives the next blinding element by squaring, and a fresh one is
* chosen every ReinitInterval calls.
*/
class DL_PrivateKey_Exponentiation final {
   public:
      static constexpr size_t ReinitInterval = 64;

      enum class Output : uint8_t {
         Power,
         InversePower,
      };

      /**
      * @note Lifetime: the rng is captured by reference and must outlive this object
      */
      DL_PrivateKey_Exponentiation(std::shared_ptr<const DL_PrivateKey> key, Output output, RandomNumberGenerator& rng);

      /**
      * Return b^x, or b^-x if the output is InversePower
      */
      DL_Element pow(const DL_Element& b);

      void _const_time_poison() const;

      void _const_time_unpoison() const;

   private:
      DL_Element unblinder(const DL_Element& e) const;

      std::shared_ptr<const DL_PrivateKey> m_key;
      RandomNumberGenerator& m_rng;
      Output m_output;
      DL_Element m_e;
      DL_Element m_d;  // e^-x for Power, e^x for InversePower
      size_t m_counter = 0;
};

}  // namespace Botan

#endif
