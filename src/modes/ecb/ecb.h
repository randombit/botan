/*
* ECB Mode
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ECB_H__
#define BOTAN_ECB_H__

#include <botan/basefilt.h>
#include <botan/block_cipher.h>
#include <botan/mode_pad.h>

#include <botan/modebase.h>

namespace Botan {

/*
* ECB Encryption
*/
class BOTAN_DLL ECB_Encryption : public Keyed_Filter
   {
   public:
      std::string name() const;

      void set_key(const SymmetricKey& key) { cipher->set_key(key); }

      bool valid_keylength(u32bit key_len) const
         { return cipher->valid_keylength(key_len); }

      ECB_Encryption(BlockCipher* ciph,
                     BlockCipherModePaddingMethod* pad);

      ECB_Encryption(BlockCipher* ciph,
                     BlockCipherModePaddingMethod* pad,
                     const SymmetricKey& key);

      ~ECB_Encryption();
   private:
      void write(const byte[], u32bit);
      void end_msg();

      BlockCipher* cipher;
      BlockCipherModePaddingMethod* padder;
      SecureVector<byte> plaintext, ciphertext;
      u32bit position;
   };

/*
* ECB Decryption
*/
class BOTAN_DLL ECB_Decryption : public Keyed_Filter
   {
   public:
      std::string name() const;

      void set_key(const SymmetricKey& key) { cipher->set_key(key); }

      bool valid_keylength(u32bit key_len) const
         { return cipher->valid_keylength(key_len); }

      ECB_Decryption(BlockCipher* ciph,
                     BlockCipherModePaddingMethod* pad);

      ECB_Decryption(BlockCipher* ciph,
                     BlockCipherModePaddingMethod* pad,
                     const SymmetricKey& key);

      ~ECB_Decryption();
   private:
      void write(const byte[], u32bit);
      void end_msg();

      BlockCipher* cipher;
      BlockCipherModePaddingMethod* padder;
      SecureVector<byte> plaintext, ciphertext;
      u32bit position;
   };

}

#endif
