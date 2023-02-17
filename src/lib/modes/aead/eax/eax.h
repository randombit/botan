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
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/mac.h>

namespace Botan {

/**
* EAX base class
*/
class EAX_Mode : public AEAD_Mode
   {
   public:
      void set_associated_data(const uint8_t ad[], size_t ad_len) override final;

      std::string name() const override final;

      size_t update_granularity() const override final;

      size_t ideal_granularity() const override final;

      Key_Length_Specification key_spec() const override final;

      // EAX supports arbitrary nonce lengths
      bool valid_nonce_length(size_t) const override final { return true; }

      size_t tag_size() const override final { return m_tag_size; }

      void clear() override final;

      void reset() override final;

      bool has_keying_material() const override final;

   protected:
      /**
      * @param cipher the cipher to use
      * @param tag_size is how big the auth tag will be
      */
      EAX_Mode(std::unique_ptr<BlockCipher> cipher, size_t tag_size);

      size_t block_size() const { return m_cipher->block_size(); }

      size_t m_tag_size;

      std::unique_ptr<BlockCipher> m_cipher;
      std::unique_ptr<StreamCipher> m_ctr;
      std::unique_ptr<MessageAuthenticationCode> m_cmac;

      secure_vector<uint8_t> m_ad_mac;

      secure_vector<uint8_t> m_nonce_mac;
   private:
      void start_msg(const uint8_t nonce[], size_t nonce_len) override final;

      void key_schedule(const uint8_t key[], size_t length) override final;
   };

/**
* EAX Encryption
*/
class EAX_Encryption final : public EAX_Mode
   {
   public:
      /**
      * @param cipher a 128-bit block cipher
      * @param tag_size is how big the auth tag will be
      */
      EAX_Encryption(std::unique_ptr<BlockCipher> cipher, size_t tag_size = 0) :
         EAX_Mode(std::move(cipher), tag_size) {}

      size_t output_length(size_t input_length) const override
         { return input_length + tag_size(); }

      size_t minimum_final_size() const override { return 0; }

      size_t process(uint8_t buf[], size_t size) override;

      void finish(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
   };

/**
* EAX Decryption
*/
class EAX_Decryption final : public EAX_Mode
   {
   public:
      /**
      * @param cipher a 128-bit block cipher
      * @param tag_size is how big the auth tag will be
      */
      EAX_Decryption(std::unique_ptr<BlockCipher> cipher, size_t tag_size = 0) :
         EAX_Mode(std::move(cipher), tag_size) {}

      size_t output_length(size_t input_length) const override
         {
         BOTAN_ARG_CHECK(input_length >= tag_size(), "Sufficient input");
         return input_length - tag_size();
         }

      size_t minimum_final_size() const override { return tag_size(); }

      size_t process(uint8_t buf[], size_t size) override;

      void finish(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
   };

}

#endif
