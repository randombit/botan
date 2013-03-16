/*
* GCM Mode
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_GCM_H__
#define BOTAN_GCM_H__

#include <botan/aead.h>
#include <botan/buf_filt.h>
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <memory>

namespace Botan {

/**
* GCM Mode
*/
class BOTAN_DLL GCM_Mode : public AEAD_Mode,
                           private Buffered_Filter
   {
   public:
      void set_key(const SymmetricKey& key) override;

      void set_nonce(const byte nonce[], size_t nonce_len) override;

      /**
      * @note must be called before start_msg or not at all
      */
      void set_associated_data(const byte ad[], size_t ad_len) override;

      bool valid_keylength(size_t key_len) const override;

      // GCM supports arbitrary IV lengths
      bool valid_iv_length(size_t) const override { return true; }

      std::string name() const override;
   protected:
      GCM_Mode(BlockCipher* cipher, size_t tag_size, bool decrypting);

      const size_t m_tag_size;
      const std::string m_cipher_name;

      std::unique_ptr<StreamCipher> m_ctr;
      secure_vector<byte> m_H;
      secure_vector<byte> m_H_ad;
      secure_vector<byte> m_H_current;
      secure_vector<byte> m_y0_cipher;
      size_t m_ad_len, m_text_len;
      secure_vector<byte> m_ctr_buf;

   private:
      void write(const byte[], size_t);
      void start_msg();
      void end_msg();
   };

/**
* GCM Encryption
*/
class BOTAN_DLL GCM_Encryption : public GCM_Mode
   {
   public:
      /**
      * @param ciph the cipher to use
      * @param tag_size is how big the auth tag will be
      */
      GCM_Encryption(BlockCipher* ciph, size_t tag_size = 16) :
         GCM_Mode(ciph, tag_size, false) {}

   private:
      void buffered_block(const byte input[], size_t input_length) override;
      void buffered_final(const byte input[], size_t input_length) override;
   };

/**
* GCM Decryption
*/
class BOTAN_DLL GCM_Decryption : public GCM_Mode
   {
   public:
      /**
      * @param ciph the cipher to use
      * @param tag_size is how big the auth tag will be
      */
      GCM_Decryption(BlockCipher* cipher, size_t tag_size = 16) :
         GCM_Mode(cipher, tag_size, true) {}

   private:
      void buffered_block(const byte input[], size_t input_length) override;
      void buffered_final(const byte input[], size_t input_length) override;
   };

}

#endif
