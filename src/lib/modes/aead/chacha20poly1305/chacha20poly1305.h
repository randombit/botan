/*
* ChaCha20Poly1305 AEAD
* (C) 2014 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_AEAD_CHACHA20_POLY1305_H_
#define BOTAN_AEAD_CHACHA20_POLY1305_H_

#include <botan/aead.h>
#include <botan/mac.h>
#include <botan/stream_cipher.h>

namespace Botan {

/**
* Base class
* See draft-irtf-cfrg-chacha20-poly1305-03 for specification
* If a nonce of 64 bits is used the older version described in
* draft-agl-tls-chacha20poly1305-04 is used instead.
* If a nonce of 192 bits is used, XChaCha20Poly1305 is selected.
*/
class ChaCha20Poly1305_Mode : public AEAD_Mode {
   public:
      void set_associated_data_n(size_t idx, std::span<const uint8_t> ad) final;

      bool associated_data_requires_key() const override { return false; }

      std::string name() const override { return "ChaCha20Poly1305"; }

      size_t update_granularity() const override;

      size_t ideal_granularity() const override;

      Key_Length_Specification key_spec() const override { return Key_Length_Specification(32); }

      bool valid_nonce_length(size_t n) const override;

      size_t tag_size() const override { return 16; }

      void clear() override;

      void reset() override;

      bool has_keying_material() const final;

   protected:
      std::unique_ptr<StreamCipher> m_chacha;
      std::unique_ptr<MessageAuthenticationCode> m_poly1305;

      ChaCha20Poly1305_Mode();

      secure_vector<uint8_t> m_ad;
      size_t m_nonce_len = 0;
      size_t m_ctext_len = 0;

      bool cfrg_version() const { return m_nonce_len == 12 || m_nonce_len == 24; }

      void update_len(size_t len);

   private:
      void start_msg(const uint8_t nonce[], size_t nonce_len) override;

      void key_schedule(std::span<const uint8_t> key) override;
};

/**
* ChaCha20Poly1305 Encryption
*/
class ChaCha20Poly1305_Encryption final : public ChaCha20Poly1305_Mode {
   public:
      size_t output_length(size_t input_length) const override { return input_length + tag_size(); }

      size_t minimum_final_size() const override { return 0; }

   private:
      size_t process_msg(uint8_t buf[], size_t size) override;
      void finish_msg(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
};

/**
* ChaCha20Poly1305 Decryption
*/
class ChaCha20Poly1305_Decryption final : public ChaCha20Poly1305_Mode {
   public:
      size_t output_length(size_t input_length) const override {
         BOTAN_ARG_CHECK(input_length >= tag_size(), "Sufficient input");
         return input_length - tag_size();
      }

      size_t minimum_final_size() const override { return tag_size(); }

   private:
      size_t process_msg(uint8_t buf[], size_t size) override;
      void finish_msg(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
};

}  // namespace Botan

#endif
