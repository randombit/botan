/*
* PKCS #1 v1.5 signature padding
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PKCS1V15_SIGNATURE_PADDING_H_
#define BOTAN_PKCS1V15_SIGNATURE_PADDING_H_

#include <botan/internal/sig_padding.h>

#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace Botan {

class HashFunction;

/**
* PKCS #1 v1.5 signature padding
* aka PKCS #1 block type 1
* aka EMSA3 from IEEE 1363
*/
class PKCS1v15_SignaturePaddingScheme final : public SignaturePaddingScheme {
   public:
      /**
      * @param hash the hash function to use
      */
      explicit PKCS1v15_SignaturePaddingScheme(std::unique_ptr<HashFunction> hash);

      void update(const uint8_t input[], size_t length) override;

      std::vector<uint8_t> raw_data() override;

      std::vector<uint8_t> encoding_of(std::span<const uint8_t> msg,
                                       size_t output_bits,
                                       RandomNumberGenerator& rng) override;

      bool verify(std::span<const uint8_t> coded, std::span<const uint8_t> raw, size_t key_bits) override;

      std::string name() const override;

      std::string hash_function() const override;

   private:
      std::unique_ptr<HashFunction> m_hash;
      std::vector<uint8_t> m_hash_id;
};

/**
* PKCS1v15_SignaturePaddingScheme_Raw which is PKCS1v15_SignaturePaddingScheme without a hash or digest id
* (which according to QCA docs is "identical to PKCS#11's CKM_RSA_PKCS
* mechanism", something I have not confirmed)
*/
class PKCS1v15_Raw_SignaturePaddingScheme final : public SignaturePaddingScheme {
   public:
      void update(const uint8_t input[], size_t length) override;

      std::vector<uint8_t> raw_data() override;

      std::vector<uint8_t> encoding_of(std::span<const uint8_t> msg,
                                       size_t output_bits,
                                       RandomNumberGenerator& rng) override;

      bool verify(std::span<const uint8_t> coded, std::span<const uint8_t> raw, size_t key_bits) override;

      PKCS1v15_Raw_SignaturePaddingScheme();

      /**
      * @param hash_algo the digest id for that hash is included in
      * the signature.
      */
      explicit PKCS1v15_Raw_SignaturePaddingScheme(std::string_view hash_algo);

      std::string hash_function() const override { return m_hash_name; }

      std::string name() const override;

   private:
      size_t m_hash_output_len = 0;
      std::string m_hash_name;
      std::vector<uint8_t> m_hash_id;
      std::vector<uint8_t> m_message;
};

}  // namespace Botan

#endif
