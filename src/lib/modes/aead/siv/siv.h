/*
* SIV Mode
* (C) 2013 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_AEAD_SIV_H_
#define BOTAN_AEAD_SIV_H_

#include <botan/aead.h>

#include <botan/assert.h>
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>

namespace Botan {

class MessageAuthenticationCode;

/**
* Base class for SIV encryption and decryption (@see RFC 5297)
*/
class BOTAN_TEST_API SIV_Mode : public AEAD_Mode /* NOLINT(*-special-member-functions) */ {
   public:
      constexpr static size_t tag_length = 16;

      /**
      * Sets the nth element of the vector of associated data
      * @param n index into the AD vector
      * @param ad associated data
      */
      void set_associated_data_n(size_t n, std::span<const uint8_t> ad) final;

      size_t maximum_associated_data_inputs() const final;

      std::string name() const final;

      size_t update_granularity() const final;

      size_t ideal_granularity() const final;

      Key_Length_Specification key_spec() const final;

      bool valid_nonce_length(size_t) const final;

      bool requires_entire_message() const final;

      void clear() final;

      void reset() final;

      size_t tag_size() const final { return 16; }

      bool has_keying_material() const final;

      ~SIV_Mode() override;

   protected:
      explicit SIV_Mode(std::unique_ptr<BlockCipher> cipher);

      size_t block_size() const { return m_bs; }

      StreamCipher& ctr() { return *m_ctr; }

      void set_ctr_iv(std::array<uint8_t, tag_length> V);

      secure_vector<uint8_t>& msg_buf() { return m_msg_buf; }

      const secure_vector<uint8_t>& msg_buf() const { return m_msg_buf; }

      std::array<uint8_t, tag_length> S2V(std::span<const uint8_t> text);

   private:
      void start_msg(const uint8_t nonce[], size_t nonce_len) final;
      size_t process_msg(uint8_t buf[], size_t size) final;

      void key_schedule(std::span<const uint8_t> key) final;

      const std::string m_name;
      const size_t m_bs;

      std::unique_ptr<StreamCipher> m_ctr;
      std::unique_ptr<MessageAuthenticationCode> m_mac;
      secure_vector<uint8_t> m_nonce, m_msg_buf;
      std::vector<secure_vector<uint8_t>> m_ad_macs;
};

/**
* SIV Encryption
*/
class BOTAN_TEST_API SIV_Encryption final : public SIV_Mode {
   public:
      /**
      * @param cipher a block cipher
      */
      explicit SIV_Encryption(std::unique_ptr<BlockCipher> cipher) : SIV_Mode(std::move(cipher)) {}

      size_t output_length(size_t input_length) const override { return input_length + tag_size(); }

      size_t bytes_needed_for_finalization(size_t final_input_length) const override {
         return output_length(msg_buf().size() + final_input_length);
      }

      size_t minimum_final_size() const override { return 0; }

   private:
      size_t finish_msg(std::span<uint8_t> final_block, size_t input_bytes) override;
};

/**
* SIV Decryption
*/
class BOTAN_TEST_API SIV_Decryption final : public SIV_Mode {
   public:
      /**
      * @param cipher a 128-bit block cipher
      */
      explicit SIV_Decryption(std::unique_ptr<BlockCipher> cipher) : SIV_Mode(std::move(cipher)) {}

      size_t output_length(size_t input_length) const override {
         BOTAN_ASSERT(input_length >= tag_size(), "Sufficient input");
         return input_length - tag_size();
      }

      size_t bytes_needed_for_finalization(size_t final_input_length) const override {
         return msg_buf().size() + final_input_length;
      }

      size_t minimum_final_size() const override { return tag_size(); }

   private:
      size_t finish_msg(std::span<uint8_t> final_block, size_t input_bytes) override;
};

}  // namespace Botan

#endif
