/*
* XTS mode, from IEEE P1619
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_XTS_H__
#define BOTAN_XTS_H__

#include <botan/block_cipher.h>
#include <botan/key_filt.h>
#include <botan/buf_filt.h>

namespace Botan {

/**
* IEEE P1619 XTS Encryption
*/
class BOTAN_DLL XTS_Encryption : public Keyed_Filter,
                                 private Buffered_Filter
   {
   public:
      void set_key(const SymmetricKey& key);
      void set_iv(const InitializationVector& iv);

      bool valid_keylength(size_t key_len) const
         { return cipher->valid_keylength(key_len); }

      bool valid_iv_length(size_t iv_len) const
         { return (iv_len == cipher->block_size()); }

      std::string name() const;

      XTS_Encryption(BlockCipher* ciph);

      XTS_Encryption(BlockCipher* ciph,
                     const SymmetricKey& key,
                     const InitializationVector& iv);

      ~XTS_Encryption() { delete cipher; delete cipher2; }
   private:
      void write(const byte[], size_t);
      void end_msg();

      void buffered_block(const byte input[], size_t input_length);
      void buffered_final(const byte input[], size_t input_length);

      BlockCipher* cipher;
      BlockCipher* cipher2;
      SecureVector<byte> tweak;
   };

/**
* IEEE P1619 XTS Encryption
*/
class BOTAN_DLL XTS_Decryption : public Keyed_Filter,
                                 private Buffered_Filter
   {
   public:
      void set_key(const SymmetricKey& key);
      void set_iv(const InitializationVector& iv);

      bool valid_keylength(size_t key_len) const
         { return cipher->valid_keylength(key_len); }

      bool valid_iv_length(size_t iv_len) const
         { return (iv_len == cipher->block_size()); }

      std::string name() const;

      XTS_Decryption(BlockCipher* ciph);

      XTS_Decryption(BlockCipher* ciph,
                     const SymmetricKey& key,
                     const InitializationVector& iv);

      ~XTS_Decryption() { delete cipher; delete cipher2; }
   private:
      void write(const byte[], size_t);
      void end_msg();

      void buffered_block(const byte input[], size_t input_length);
      void buffered_final(const byte input[], size_t input_length);

      BlockCipher* cipher;
      BlockCipher* cipher2;
      SecureVector<byte> tweak;
   };

}

#endif
