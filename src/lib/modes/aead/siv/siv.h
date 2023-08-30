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
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>

namespace Botan {

class MessageAuthenticationCode;

/**
* Base class for SIV encryption and decryption (@see RFC 5297)
*/
class BOTAN_TEST_API SIV_Mode : public AEAD_Mode {
   public:
      /**
      * Sets the nth element of the vector of associated data
      * @param n index into the AD vector
      * @param ad associated data
      */
      void set_associated_data_n(size_t n, std::span<const uint8_t> ad) override final;

      size_t maximum_associated_data_inputs() const override final;

      std::string name() const override final;

      size_t update_granularity() const override final;

      size_t ideal_granularity() const override final;

      Key_Length_Specification key_spec() const override final;

      bool valid_nonce_length(size_t) const override final;

      bool requires_entire_message() const override final;

      void clear() override final;

      void reset() override final;

      size_t tag_size() const override final { return 16; }

      bool has_keying_material() const override final;

      ~SIV_Mode();

   protected:
      explicit SIV_Mode(std::unique_ptr<BlockCipher> cipher);

      size_t block_size() const { return m_bs; }

      StreamCipher& ctr() { return *m_ctr; }

      void set_ctr_iv(secure_vector<uint8_t> V);

      secure_vector<uint8_t>& msg_buf() { return m_msg_buf; }

      secure_vector<uint8_t> S2V(const uint8_t text[], size_t text_len);

   private:
      void start_msg(const uint8_t nonce[], size_t nonce_len) override final;
      size_t process_msg(uint8_t buf[], size_t size) override final;

      void key_schedule(std::span<const uint8_t> key) override final;

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

      size_t minimum_final_size() const override { return 0; }

   private:
      void finish_msg(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
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

      size_t minimum_final_size() const override { return tag_size(); }

   private:
      void finish_msg(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
};

}  // namespace Botan

#endif
