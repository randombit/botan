/*
* CTS Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CTS_H__
#define BOTAN_CTS_H__

#include <botan/block_cipher.h>
#include <botan/key_filt.h>

namespace Botan {

/**
* CBC encryption with ciphertext stealing
*/
class BOTAN_DLL CTS_Encryption : public Keyed_Filter
   {
   public:
      std::string name() const { return cipher->name() + "/CTS"; }

      void set_iv(const InitializationVector&);

      void set_key(const SymmetricKey& key) { cipher->set_key(key); }

      bool valid_keylength(size_t key_len) const
         { return cipher->valid_keylength(key_len); }

      bool valid_iv_length(size_t iv_len) const
         { return (iv_len == cipher->block_size()); }

      CTS_Encryption(BlockCipher* cipher);

      CTS_Encryption(BlockCipher* cipher,
                     const SymmetricKey& key,
                     const InitializationVector& iv);

      ~CTS_Encryption() { delete cipher; }
   private:
      void write(const byte[], size_t);
      void end_msg();
      void encrypt(const byte[]);

      BlockCipher* cipher;
      SecureVector<byte> buffer, state;
      size_t position;
   };

/**
* CBC decryption with ciphertext stealing
*/
class BOTAN_DLL CTS_Decryption : public Keyed_Filter
   {
   public:
      std::string name() const { return cipher->name() + "/CTS"; }

      void set_iv(const InitializationVector&);

      void set_key(const SymmetricKey& key) { cipher->set_key(key); }

      bool valid_keylength(size_t key_len) const
         { return cipher->valid_keylength(key_len); }

      bool valid_iv_length(size_t iv_len) const
         { return (iv_len == cipher->block_size()); }

      CTS_Decryption(BlockCipher* cipher);

      CTS_Decryption(BlockCipher* cipher,
                     const SymmetricKey& key,
                     const InitializationVector& iv);

      ~CTS_Decryption() { delete cipher; }
   private:
      void write(const byte[], size_t);
      void end_msg();
      void decrypt(const byte[]);

      BlockCipher* cipher;
      SecureVector<byte> buffer, state, temp;
      size_t position;
   };

}

#endif
