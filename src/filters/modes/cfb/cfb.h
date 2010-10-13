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

      bool valid_keylength(size_t key_len) const
         { return cipher->valid_keylength(key_len); }

      bool valid_iv_length(size_t iv_len) const
         { return (iv_len == cipher->block_size()); }

      CFB_Encryption(BlockCipher* cipher, size_t feedback = 0);

      CFB_Encryption(BlockCipher* cipher,
                     const SymmetricKey& key,
                     const InitializationVector& iv,
                     size_t feedback = 0);

      ~CFB_Encryption() { delete cipher; }
   private:
      void write(const byte[], size_t);

      BlockCipher* cipher;
      SecureVector<byte> buffer, state;
      size_t position, feedback;
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

      bool valid_keylength(size_t key_len) const
         { return cipher->valid_keylength(key_len); }

      bool valid_iv_length(size_t iv_len) const
         { return (iv_len == cipher->block_size()); }

      CFB_Decryption(BlockCipher* cipher, size_t feedback = 0);

      CFB_Decryption(BlockCipher* cipher,
                     const SymmetricKey& key,
                     const InitializationVector& iv,
                     size_t feedback = 0);

      ~CFB_Decryption() { delete cipher; }
   private:
      void write(const byte[], size_t);

      BlockCipher* cipher;
      SecureVector<byte> buffer, state;
      size_t position, feedback;
   };

}

#endif
