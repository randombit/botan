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
      void set_header(const byte header[], u32bit header_len);

      /**
      * @return name of this mode
      */
      std::string name() const;

      bool valid_keylength(u32bit key_len) const;

      ~EAX_Base() { delete ctr; delete cmac; }
   protected:
      /**
      * @param cipher the cipher to use
      * @param tag_size is how big the auth tag will be
      */
      EAX_Base(BlockCipher* cipher, u32bit tag_size);
      void start_msg();

      const u32bit BLOCK_SIZE, TAG_SIZE;
      std::string cipher_name;

      StreamCipher* ctr;
      MessageAuthenticationCode* cmac;

      SecureVector<byte> nonce_mac, header_mac;
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
      EAX_Encryption(BlockCipher* ciph, u32bit tag_size = 0) :
         EAX_Base(ciph, tag_size) {}

      /**
      * @param ciph the cipher to use
      * @param key the key to use
      * @param iv the initially set IV
      * @param tag_size is how big the auth tag will be
      */
      EAX_Encryption(BlockCipher* ciph, const SymmetricKey& key,
                     const InitializationVector& iv,
                     u32bit tag_size) : EAX_Base(ciph, tag_size)
         {
         set_key(key);
         set_iv(iv);
         }
   private:
      void write(const byte[], u32bit);
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
      EAX_Decryption(BlockCipher* ciph, u32bit tag_size = 0);

      /**
      * @param ciph the cipher to use
      * @param key the key to use
      * @param iv the initially set IV
      * @param tag_size is how big the auth tag will be
      */
      EAX_Decryption(BlockCipher* ciph, const SymmetricKey& key,
                     const InitializationVector& iv,
                     u32bit tag_size = 0);
   private:
      void write(const byte[], u32bit);
      void do_write(const byte[], u32bit);
      void end_msg();

      SecureVector<byte> queue;
      u32bit queue_start, queue_end;
   };

}

#endif
