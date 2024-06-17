/*
* KDF defined in NIST SP 800-56a revision 2 (Single-step key-derivation function)
* or in NIST SP 800-56C revision 2 (Section 4 - One-Step KDM)
*
* (C) 2017 Ribose Inc. Written by Krzysztof Kwiatkowski.
* (C) 2024 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SP800_56A_H_
#define BOTAN_SP800_56A_H_

#include <botan/hash.h>
#include <botan/kdf.h>
#include <botan/mac.h>

namespace Botan {

/**
 * NIST SP 800-56Cr2 One-Step KDF using hash function
 * @warning The salt for this KDF must be empty.
 */
class SP800_56C_One_Step_Hash final : public KDF {
   public:
      std::string name() const override;

      std::unique_ptr<KDF> new_object() const override;

      /**
      * Derive a key using the SP800-56Cr2 One-Step KDF.
      *
      * @param key DerivedKeyingMaterial output buffer
      * @param key_len the desired output length in bytes
      * @param secret shared secret Z
      * @param secret_len size of Z in bytes
      * @param salt the salt. Ignored.
      * @param salt_len size of salt in bytes. Must be 0.
      * @param label FixedInfo
      * @param label_len size of label in bytes
      *
      * @throws Invalid_Argument if key_len > (2^32 - 1) * Hash output bits.
      *         Or thrown if salt is non-empty
      */
      void kdf(uint8_t key[],
               size_t key_len,
               const uint8_t secret[],
               size_t secret_len,
               const uint8_t salt[],
               size_t salt_len,
               const uint8_t label[],
               size_t label_len) const override;

      /**
      * @param hash the hash function to use as the auxiliary function
      */
      explicit SP800_56C_One_Step_Hash(std::unique_ptr<HashFunction> hash) : m_hash(std::move(hash)) {}

   private:
      std::unique_ptr<HashFunction> m_hash;
};

/**
 * NIST SP800-56Cr2 One-Step KDF using HMAC
 */
class SP800_56C_One_Step_HMAC final : public KDF {
   public:
      std::string name() const override;

      std::unique_ptr<KDF> new_object() const override;

      /**
      * Derive a key using the SP800-56Cr2 One-Step KDF.
      *
      * @param key DerivedKeyingMaterial output buffer
      * @param key_len the desired output length in bytes
      * @param secret shared secret Z
      * @param secret_len size of Z in bytes
      * @param salt the salt. If empty the default_salt is used.
      * @param salt_len size of salt in bytes
      * @param label FixedInfo
      * @param label_len size of label in bytes
      *
      * @throws Invalid_Argument if key_len > (2^32 - 1) * HMAC output bits
      */
      void kdf(uint8_t key[],
               size_t key_len,
               const uint8_t secret[],
               size_t secret_len,
               const uint8_t salt[],
               size_t salt_len,
               const uint8_t label[],
               size_t label_len) const override;

      /**
      * @param mac the HMAC to use as the auxiliary function
      */
      explicit SP800_56C_One_Step_HMAC(std::unique_ptr<MessageAuthenticationCode> mac);

   private:
      std::unique_ptr<MessageAuthenticationCode> m_mac;
};

/**
 * NIST SP800-56Cr2 One-Step KDF using KMAC (Abstract class)
 */
class SP800_56A_One_Step_KMAC_Abstract : public KDF {
   public:
      /**
      * Derive a key using the SP800-56Cr2 One-Step KDF.
      *
      * @param key DerivedKeyingMaterial output buffer
      * @param key_len the desired output length in bytes
      * @param secret shared secret Z
      * @param secret_len size of Z in bytes
      * @param salt the salt. If empty the default_salt is used.
      * @param salt_len size of salt in bytes
      * @param label FixedInfo
      * @param label_len size of label in bytes
      *
      * @throws Invalid_Argument if key_len > (2^32 - 1) * KMAC output bits
      */
      void kdf(uint8_t key[],
               size_t key_len,
               const uint8_t secret[],
               size_t secret_len,
               const uint8_t salt[],
               size_t salt_len,
               const uint8_t label[],
               size_t label_len) const override;

   protected:
      virtual std::unique_ptr<MessageAuthenticationCode> create_kmac_instance(size_t output_byte_len) const = 0;

      /// See SP800-56C Section 4.1 - Implementation-Dependent Parameters 3.
      virtual size_t default_salt_length() const = 0;
};

/**
 * NIST SP800-56Cr2 One-Step KDF using KMAC-128
 */
class SP800_56C_One_Step_KMAC128 final : public SP800_56A_One_Step_KMAC_Abstract {
   public:
      std::string name() const override { return "SP800-56A(KMAC-128)"; }

      std::unique_ptr<KDF> new_object() const override { return std::make_unique<SP800_56C_One_Step_KMAC128>(); }

   private:
      std::unique_ptr<MessageAuthenticationCode> create_kmac_instance(size_t output_byte_len) const override;

      size_t default_salt_length() const override { return 164; }
};

/**
 * NIST SP800-56Cr2 One-Step KDF using KMAC-256
 */
class SP800_56C_One_Step_KMAC256 final : public SP800_56A_One_Step_KMAC_Abstract {
   public:
      std::string name() const override { return "SP800-56A(KMAC-256)"; }

      std::unique_ptr<KDF> new_object() const override { return std::make_unique<SP800_56C_One_Step_KMAC256>(); }

   private:
      std::unique_ptr<MessageAuthenticationCode> create_kmac_instance(size_t output_byte_len) const override;

      size_t default_salt_length() const override { return 132; }
};

}  // namespace Botan

#endif
