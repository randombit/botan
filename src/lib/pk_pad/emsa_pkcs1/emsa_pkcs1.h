/*
* PKCS #1 v1.5 signature padding
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EMSA_PKCS1_H_
#define BOTAN_EMSA_PKCS1_H_

#include <botan/hash.h>
#include <botan/internal/emsa.h>
#include <optional>

namespace Botan {

/**
* PKCS #1 v1.5 signature padding
* aka PKCS #1 block type 1
* aka EMSA3 from IEEE 1363
*/
class EMSA_PKCS1v15 final : public EMSA {
   public:
      /**
      * @param hash the hash function to use
      */
      explicit EMSA_PKCS1v15(std::unique_ptr<HashFunction> hash);

      void update(const uint8_t[], size_t) override;

      std::vector<uint8_t> raw_data() override;

      std::vector<uint8_t> encoding_of(const std::vector<uint8_t>&, size_t, RandomNumberGenerator& rng) override;

      bool verify(const std::vector<uint8_t>&, const std::vector<uint8_t>&, size_t) override;

      std::string name() const override { return "EMSA3(" + m_hash->name() + ")"; }

      std::string hash_function() const override { return m_hash->name(); }

   private:
      std::unique_ptr<HashFunction> m_hash;
      std::vector<uint8_t> m_hash_id;
};

/**
* EMSA_PKCS1v15_Raw which is EMSA_PKCS1v15 without a hash or digest id
* (which according to QCA docs is "identical to PKCS#11's CKM_RSA_PKCS
* mechanism", something I have not confirmed)
*/
class EMSA_PKCS1v15_Raw final : public EMSA {
   public:
      void update(const uint8_t[], size_t) override;

      std::vector<uint8_t> raw_data() override;

      std::vector<uint8_t> encoding_of(const std::vector<uint8_t>&, size_t, RandomNumberGenerator& rng) override;

      bool verify(const std::vector<uint8_t>&, const std::vector<uint8_t>&, size_t) override;

      /**
      * @param hash_algo the digest id for that hash is included in
      * the signature.
      */
      EMSA_PKCS1v15_Raw(const std::optional<std::string>& hash_algo = std::nullopt);

      std::string hash_function() const override { return m_hash_name; }

      std::string name() const override {
         if(m_hash_name.empty()) {
            return "EMSA3(Raw)";
         } else {
            return "EMSA3(Raw," + m_hash_name + ")";
         }
      }

   private:
      size_t m_hash_output_len = 0;
      std::string m_hash_name;
      std::vector<uint8_t> m_hash_id;
      std::vector<uint8_t> m_message;
};

}  // namespace Botan

#endif
