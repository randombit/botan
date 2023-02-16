/*
* CCM Mode
* (C) 2013 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_AEAD_CCM_H_
#define BOTAN_AEAD_CCM_H_

#include <botan/aead.h>
#include <botan/block_cipher.h>

namespace Botan {

/**
* Base class for CCM encryption and decryption
* @see RFC 3610
*/
class CCM_Mode : public AEAD_Mode
   {
   public:
      size_t process(uint8_t buf[], size_t sz) override final;

      void set_associated_data(const uint8_t ad[], size_t ad_len) override final;

      bool associated_data_requires_key() const override final { return false; }

      std::string name() const override final;

      size_t update_granularity() const override final;

      size_t ideal_granularity() const override final;

      bool requires_entire_message() const override final;

      Key_Length_Specification key_spec() const override final;

      bool valid_nonce_length(size_t) const override final;

      size_t default_nonce_length() const override final;

      void clear() override final;

      void reset() override final;

      size_t tag_size() const override final { return m_tag_size; }

      bool has_keying_material() const override final;
   protected:
      CCM_Mode(std::unique_ptr<BlockCipher> cipher, size_t tag_size, size_t L);

      size_t L() const { return m_L; }

      const BlockCipher& cipher() const { return *m_cipher; }

      void encode_length(uint64_t len, uint8_t out[]);

      static void inc(secure_vector<uint8_t>& C);

      const secure_vector<uint8_t>& ad_buf() const { return m_ad_buf; }

      secure_vector<uint8_t>& msg_buf() { return m_msg_buf; }

      secure_vector<uint8_t> format_b0(size_t msg_size);
      secure_vector<uint8_t> format_c0();
   private:
      void start_msg(const uint8_t nonce[], size_t nonce_len) override final;

      void key_schedule(const uint8_t key[], size_t length) override final;

      const size_t m_tag_size;
      const size_t m_L;

      std::unique_ptr<BlockCipher> m_cipher;
      secure_vector<uint8_t> m_nonce, m_msg_buf, m_ad_buf;
   };

/**
* CCM Encryption
*/
class CCM_Encryption final : public CCM_Mode
   {
   public:
      /**
      * @param cipher a 128-bit block cipher
      * @param tag_size is how big the auth tag will be (even values
      *                 between 4 and 16 are accepted)
      * @param L length of L parameter. The total message length
      *           must be less than 2**L bytes, and the nonce is 15-L bytes.
      */
      CCM_Encryption(std::unique_ptr<BlockCipher> cipher, size_t tag_size = 16, size_t L = 3) :
         CCM_Mode(std::move(cipher), tag_size, L) {}

      void finish(secure_vector<uint8_t>& final_block, size_t offset = 0) override;

      size_t output_length(size_t input_length) const override
         { return input_length + tag_size(); }

      size_t minimum_final_size() const override { return 0; }
   };

/**
* CCM Decryption
*/
class CCM_Decryption final : public CCM_Mode
   {
   public:
      /**
      * @param cipher a 128-bit block cipher
      * @param tag_size is how big the auth tag will be (even values
      *                 between 4 and 16 are accepted)
      * @param L length of L parameter. The total message length
      *           must be less than 2**L bytes, and the nonce is 15-L bytes.
      */
      CCM_Decryption(std::unique_ptr<BlockCipher> cipher, size_t tag_size = 16, size_t L = 3) :
         CCM_Mode(std::move(cipher), tag_size, L) {}

      void finish(secure_vector<uint8_t>& final_block, size_t offset = 0) override;

      size_t output_length(size_t input_length) const override
         {
         BOTAN_ARG_CHECK(input_length >= tag_size(), "Sufficient input");
         return input_length - tag_size();
         }

      size_t minimum_final_size() const override { return tag_size(); }
   };

}

#endif
