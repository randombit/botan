/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DL_SCHEME_H_
#define BOTAN_DL_SCHEME_H_

#include <botan/bigint.h>
#include <botan/dl_group.h>
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
      const BigInt m_public_key;
};

}  // namespace Botan

#endif
