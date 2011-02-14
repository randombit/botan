/*
* EAX Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_EAX_H__
#define BOTAN_EAX_H__

#include <botan/key_filt.h>
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/mac.h>

namespace Botan {

/**
* EAX Base Class
*/
class BOTAN_DLL EAX_Base : public Keyed_Filter
   {
   public:
      void set_key(const SymmetricKey& key);
      void set_iv(const InitializationVector& iv);

      /**
      * Set some additional data that is not included in the
      * ciphertext but that will be authenticated.
      * @param header the header contents
      * @param header_len length of header in bytes
      */
      void set_header(const byte header[], size_t header_len);

      /**
      * @return name of this mode
      */
      std::string name() const;

      bool valid_keylength(size_t key_len) const;

      /**
      * EAX supports arbitrary IV lengths
      */
      bool valid_iv_length(size_t) const { return true; }

      ~EAX_Base() { delete ctr; delete cmac; }
   protected:
      /**
      * @param cipher the cipher to use
      * @param tag_size is how big the auth tag will be
      */
      EAX_Base(BlockCipher* cipher, size_t tag_size);
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
      StreamCipher* ctr;

      /**
      * The MAC (CMAC)
      */
      MessageAuthenticationCode* cmac;

      /**
      * The MAC of the nonce
      */
      SecureVector<byte> nonce_mac;

      /**
      * The MAC of the header
      */
      SecureVector<byte> header_mac;

      /**
      * A buffer for CTR mode encryption
      */
      SecureVector<byte> ctr_buf;
   };

/**
* EAX Encryption
*/
class BOTAN_DLL EAX_Encryption : public EAX_Base
   {
   public:
      /**
      * @param ciph the cipher to use
      * @param tag_size is how big the auth tag will be
      */
      EAX_Encryption(BlockCipher* ciph, size_t tag_size = 0) :
         EAX_Base(ciph, tag_size) {}

      /**
      * @param ciph the cipher to use
      * @param key the key to use
      * @param iv the initially set IV
      * @param tag_size is how big the auth tag will be
      */
      EAX_Encryption(BlockCipher* ciph, const SymmetricKey& key,
                     const InitializationVector& iv,
                     size_t tag_size) : EAX_Base(ciph, tag_size)
         {
         set_key(key);
         set_iv(iv);
         }
   private:
      void write(const byte[], size_t);
      void end_msg();
   };

/**
* EAX Decryption
*/
class BOTAN_DLL EAX_Decryption : public EAX_Base
   {
   public:
      /**
      * @param ciph the cipher to use
      * @param tag_size is how big the auth tag will be
      */
      EAX_Decryption(BlockCipher* ciph, size_t tag_size = 0);

      /**
      * @param ciph the cipher to use
      * @param key the key to use
      * @param iv the initially set IV
      * @param tag_size is how big the auth tag will be
      */
      EAX_Decryption(BlockCipher* ciph, const SymmetricKey& key,
                     const InitializationVector& iv,
                     size_t tag_size = 0);
   private:
      void write(const byte[], size_t);
      void do_write(const byte[], size_t);
      void end_msg();

      SecureVector<byte> queue;
      size_t queue_start, queue_end;
   };

}

#endif
