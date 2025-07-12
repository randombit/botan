/*
* EAX Mode
* (C) 1999-2007,2013 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_AEAD_EAX_H_
#define BOTAN_AEAD_EAX_H_

#include <botan/aead.h>

#include <botan/assert.h>
#include <botan/block_cipher.h>
#include <botan/mac.h>
#include <botan/stream_cipher.h>

namespace Botan {

/**
* EAX base class
*/
class EAX_Mode : public AEAD_Mode {
   public:
      void set_associated_data_n(size_t idx, std::span<const uint8_t> ad) final;

      std::string name() const final;

      size_t update_granularity() const final;

      size_t ideal_granularity() const final;

      Key_Length_Specification key_spec() const final;

      // EAX supports arbitrary nonce lengths
      bool valid_nonce_length(size_t) const final { return true; }

      size_t tag_size() const final { return m_tag_size; }

      void clear() final;

      void reset() final;

      bool has_keying_material() const final;

   protected:
      /**
      * @param cipher the cipher to use
      * @param tag_size is how big the auth tag will be
      */
      EAX_Mode(std::unique_ptr<BlockCipher> cipher, size_t tag_size);

      size_t block_size() const { return m_cipher->block_size(); }

      size_t m_tag_size;  // NOLINT(*non-private-member-variable*)

      std::unique_ptr<BlockCipher> m_cipher;              // NOLINT(*non-private-member-variable*)
      std::unique_ptr<StreamCipher> m_ctr;                // NOLINT(*non-private-member-variable*)
      std::unique_ptr<MessageAuthenticationCode> m_cmac;  // NOLINT(*non-private-member-variable*)

      secure_vector<uint8_t> m_ad_mac;  // NOLINT(*non-private-member-variable*)

      secure_vector<uint8_t> m_nonce_mac;  // NOLINT(*non-private-member-variable*)

   private:
      void start_msg(const uint8_t nonce[], size_t nonce_len) final;

      void key_schedule(std::span<const uint8_t> key) final;
};

/**
* EAX Encryption
*/
class EAX_Encryption final : public EAX_Mode {
   public:
      /**
      * @param cipher a 128-bit block cipher
      * @param tag_size is how big the auth tag will be
      */
      explicit EAX_Encryption(std::unique_ptr<BlockCipher> cipher, size_t tag_size = 0) :
            EAX_Mode(std::move(cipher), tag_size) {}

      size_t output_length(size_t input_length) const override { return input_length + tag_size(); }

      size_t bytes_needed_for_finalization(size_t final_input_length) const override {
         return output_length(final_input_length);
      }

      size_t minimum_final_size() const override { return 0; }

   private:
      size_t process_msg(uint8_t buf[], size_t size) override;
      size_t finish_msg(std::span<uint8_t> final_block, size_t input_bytes) override;
};

/**
* EAX Decryption
*/
class EAX_Decryption final : public EAX_Mode {
   public:
      /**
      * @param cipher a 128-bit block cipher
      * @param tag_size is how big the auth tag will be
      */
      explicit EAX_Decryption(std::unique_ptr<BlockCipher> cipher, size_t tag_size = 0) :
            EAX_Mode(std::move(cipher), tag_size) {}

      size_t output_length(size_t input_length) const override {
         BOTAN_ARG_CHECK(input_length >= tag_size(), "Sufficient input");
         return input_length - tag_size();
      }

      size_t bytes_needed_for_finalization(size_t final_input_length) const override {
         BOTAN_ARG_CHECK(final_input_length >= tag_size(), "Sufficient input");
         return final_input_length;
      }

      size_t minimum_final_size() const override { return tag_size(); }

   private:
      size_t process_msg(uint8_t buf[], size_t size) override;
      size_t finish_msg(std::span<uint8_t> final_block, size_t input_bytes) override;
};

}  // namespace Botan

#endif
