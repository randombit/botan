/*
* GCM Mode
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_GCM_H__
#define BOTAN_GCM_H__

#include <botan/aead.h>
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <memory>

namespace Botan {

/**
* GCM Mode
*/
class BOTAN_DLL GCM_Mode : public AEAD_Mode
   {
   public:
      secure_vector<byte> start(const byte nonce[], size_t nonce_len) override;

      void set_associated_data(const byte ad[], size_t ad_len) override;

      std::string name() const override;

      size_t update_granularity() const;

      Key_Length_Specification key_spec() const override;

      // GCM supports arbitrary nonce lengths
      bool valid_nonce_length(size_t) const override { return true; }

      void clear();
   protected:
      void key_schedule(const byte key[], size_t length) override;

      GCM_Mode(BlockCipher* cipher, size_t tag_size);

      size_t tag_size() const { return m_tag_size; }

      static const size_t BS = 16;

      const size_t m_tag_size;
      const std::string m_cipher_name;

      std::unique_ptr<StreamCipher> m_ctr;
      secure_vector<byte> m_H;
      secure_vector<byte> m_H_ad;
      secure_vector<byte> m_mac;
      secure_vector<byte> m_enc_y0;
      size_t m_ad_len, m_text_len;
   };

/**
* GCM Encryption
*/
class BOTAN_DLL GCM_Encryption : public GCM_Mode
   {
   public:
      /**
      * @param cipher the 128 bit block cipher to use
      * @param tag_size is how big the auth tag will be
      */
      GCM_Encryption(BlockCipher* cipher, size_t tag_size = 16) :
         GCM_Mode(cipher, tag_size) {}

      size_t minimum_final_size() const override { return 0; }

      void update(secure_vector<byte>& blocks, size_t offset) override;

      void finish(secure_vector<byte>& final_block, size_t offset) override;
   };

/**
* GCM Decryption
*/
class BOTAN_DLL GCM_Decryption : public GCM_Mode
   {
   public:
      /**
      * @param cipher the 128 bit block cipher to use
      * @param tag_size is how big the auth tag will be
      */
      GCM_Decryption(BlockCipher* cipher, size_t tag_size = 16) :
         GCM_Mode(cipher, tag_size) {}

      size_t minimum_final_size() const override { return tag_size(); }

      void update(secure_vector<byte>& blocks, size_t offset) override;

      void finish(secure_vector<byte>& final_block, size_t offset) override;
   };

}

#endif
