/*
* EAX Mode
* (C) 1999-2007,2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_EAX_H__
#define BOTAN_EAX_H__

#include <botan/aead.h>
#include <botan/buf_filt.h>
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/mac.h>
#include <memory>

namespace Botan {

/**
* EAX Mode
*/
class BOTAN_DLL EAX_Mode : public AEAD_Mode,
                           private Buffered_Filter
   {
   public:
      void set_key(const SymmetricKey& key) override;

      void set_nonce(const byte nonce[], size_t nonce_len) override;

      void set_associated_data(const byte ad[], size_t ad_len) override;

      std::string name() const override;

      bool valid_keylength(size_t key_len) const override;

      // EAX supports arbitrary IV lengths
      bool valid_iv_length(size_t) const override { return true; }
   protected:
      /**
      * @param cipher the cipher to use
      * @param tag_size is how big the auth tag will be
      */
      EAX_Mode(BlockCipher* cipher, size_t tag_size, bool decrypting);

      void start_msg();

      /**
      * The block size of the underlying cipher
      */
      const size_t BLOCK_SIZE;

      /**
      * The requested tag name
      */
      const size_t TAG_SIZE;

      /**
      * The name of the cipher
      */
      std::string cipher_name;

      /**
      * The stream cipher (CTR mode)
      */
      std::unique_ptr<StreamCipher> ctr;

      /**
      * The MAC (CMAC)
      */
      std::unique_ptr<MessageAuthenticationCode> cmac;

      /**
      * The MAC of the nonce
      */
      secure_vector<byte> nonce_mac;

      /**
      * The MAC of the associated data
      */
      secure_vector<byte> ad_mac;

      /**
      * A buffer for CTR mode encryption
      */
      secure_vector<byte> ctr_buf;
   private:
      void write(const byte[], size_t);
      void end_msg();
   };

/**
* EAX Encryption
*/
class BOTAN_DLL EAX_Encryption : public EAX_Mode
   {
   public:
      /**
      * @param ciph the cipher to use
      * @param tag_size is how big the auth tag will be
      */
      EAX_Encryption(BlockCipher* ciph, size_t tag_size = 0) :
         EAX_Mode(ciph, tag_size, false) {}

   private:
      void buffered_block(const byte input[], size_t input_length) override;
      void buffered_final(const byte input[], size_t input_length) override;
   };

/**
* EAX Decryption
*/
class BOTAN_DLL EAX_Decryption : public EAX_Mode
   {
   public:
      /**
      * @param ciph the cipher to use
      * @param tag_size is how big the auth tag will be
      */
      EAX_Decryption(BlockCipher* cipher, size_t tag_size = 0) :
         EAX_Mode(cipher, tag_size, true) {}

   private:
      void buffered_block(const byte input[], size_t input_length) override;
      void buffered_final(const byte input[], size_t input_length) override;
   };

}

#endif
