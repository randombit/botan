/*
* CFB Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CFB_H__
#define BOTAN_CFB_H__

#include <botan/block_cipher.h>
#include <botan/key_filt.h>

namespace Botan {

/**
* CFB Encryption
*/
class BOTAN_DLL CFB_Encryption : public Keyed_Filter
   {
   public:
      std::string name() const { return cipher->name() + "/CFB"; }

      void set_iv(const InitializationVector&);

      void set_key(const SymmetricKey& key) { cipher->set_key(key); }

      bool valid_keylength(u32bit key_len) const
         { return cipher->valid_keylength(key_len); }

      bool valid_iv_length(u32bit iv_len) const
         { return (iv_len == cipher->BLOCK_SIZE); }

      CFB_Encryption(BlockCipher* cipher, u32bit feedback = 0);

      CFB_Encryption(BlockCipher* cipher,
                     const SymmetricKey& key,
                     const InitializationVector& iv,
                     u32bit feedback = 0);

      ~CFB_Encryption() { delete cipher; }
   private:
      void write(const byte[], u32bit);

      BlockCipher* cipher;
      SecureVector<byte> buffer, state;
      u32bit position, feedback;
   };

/**
* CFB Decryption
*/
class BOTAN_DLL CFB_Decryption : public Keyed_Filter
   {
   public:
      std::string name() const { return cipher->name() + "/CFB"; }

      void set_iv(const InitializationVector&);

      void set_key(const SymmetricKey& key) { cipher->set_key(key); }

      bool valid_keylength(u32bit key_len) const
         { return cipher->valid_keylength(key_len); }

      bool valid_iv_length(u32bit iv_len) const
         { return (iv_len == cipher->BLOCK_SIZE); }

      CFB_Decryption(BlockCipher* cipher, u32bit feedback = 0);

      CFB_Decryption(BlockCipher* cipher,
                     const SymmetricKey& key,
                     const InitializationVector& iv,
                     u32bit feedback = 0);

      ~CFB_Decryption() { delete cipher; }
   private:
      void write(const byte[], u32bit);

      BlockCipher* cipher;
      SecureVector<byte> buffer, state;
      u32bit position, feedback;
   };

}

#endif
