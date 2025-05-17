/*
* TLS Null Cipher Handling
* (C) 2024 Sebastian Ahrens, Dirk Dobkowitz, André Schomburg (Volkswagen AG)
* (C) 2024 Lars Dürkop (CARIAD SE)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_NULL_HMAC_AEAD_H_
#define BOTAN_TLS_NULL_HMAC_AEAD_H_

#include <botan/aead.h>
#include <botan/mac.h>
#include <botan/tls_version.h>

namespace Botan::TLS {

/**
* TLS NULL+HMAC AEAD base class (GenericStreamCipher in TLS spec)
*/
class BOTAN_TEST_API TLS_NULL_HMAC_AEAD_Mode : public AEAD_Mode {
   public:
      std::string name() const final;

      void set_associated_data_n(size_t idx, std::span<const uint8_t> ad) override;

      size_t update_granularity() const final;

      size_t ideal_granularity() const final;

      Key_Length_Specification key_spec() const final;

      bool valid_nonce_length(size_t nl) const final;

      size_t tag_size() const final { return m_tag_size; }

      void clear() final;

      void reset() final;

      bool has_keying_material() const final;

   protected:
      TLS_NULL_HMAC_AEAD_Mode(std::unique_ptr<MessageAuthenticationCode> mac, size_t mac_keylen);

      size_t mac_keylen() const;

      MessageAuthenticationCode& mac() const;

   private:
      void start_msg(const uint8_t nonce[], size_t nonce_len) final;
      size_t process_msg(uint8_t buf[], size_t sz) final;

      void key_schedule(std::span<const uint8_t> key) final;

      const std::string m_mac_name;
      size_t m_mac_keylen;
      size_t m_tag_size;

      secure_vector<uint8_t> m_key;
      std::unique_ptr<MessageAuthenticationCode> m_mac;
};

/**
* TLS_NULL_HMAC_AEAD Encryption
*/
class BOTAN_TEST_API TLS_NULL_HMAC_AEAD_Encryption final : public TLS_NULL_HMAC_AEAD_Mode {
   public:
      TLS_NULL_HMAC_AEAD_Encryption(std::unique_ptr<MessageAuthenticationCode> mac, const size_t mac_keylen) :
            TLS_NULL_HMAC_AEAD_Mode(std::move(mac), mac_keylen) {}

      void set_associated_data_n(size_t idx, std::span<const uint8_t> ad) override;

      size_t output_length(size_t input_length) const override;

      size_t minimum_final_size() const override { return 0; }

   private:
      void finish_msg(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
};

/**
* TLS_NULL_HMAC_AEAD Decryption
*/
class BOTAN_TEST_API TLS_NULL_HMAC_AEAD_Decryption final : public TLS_NULL_HMAC_AEAD_Mode {
   public:
      TLS_NULL_HMAC_AEAD_Decryption(std::unique_ptr<MessageAuthenticationCode> mac, const size_t mac_keylen) :
            TLS_NULL_HMAC_AEAD_Mode(std::move(mac), mac_keylen) {}

      size_t output_length(size_t input_length) const override;

      size_t minimum_final_size() const override { return tag_size(); }

      void finish_msg(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
};

}  // namespace Botan::TLS

#endif
