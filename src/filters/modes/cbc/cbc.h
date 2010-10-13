/*
* CBC Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CBC_H__
#define BOTAN_CBC_H__

#include <botan/block_cipher.h>
#include <botan/key_filt.h>
#include <botan/mode_pad.h>
#include <botan/buf_filt.h>

namespace Botan {

/**
* CBC Encryption
*/
class BOTAN_DLL CBC_Encryption : public Keyed_Filter,
                                 private Buffered_Filter
   {
   public:
      std::string name() const;

      void set_iv(const InitializationVector& iv);

      void set_key(const SymmetricKey& key) { cipher->set_key(key); }

      bool valid_keylength(size_t key_len) const
         { return cipher->valid_keylength(key_len); }

      bool valid_iv_length(size_t iv_len) const
         { return (iv_len == cipher->block_size()); }

      CBC_Encryption(BlockCipher* cipher,
                     BlockCipherModePaddingMethod* padding);

      CBC_Encryption(BlockCipher* cipher,
                     BlockCipherModePaddingMethod* padding,
                     const SymmetricKey& key,
                     const InitializationVector& iv);

      ~CBC_Encryption() { delete cipher; delete padder; }
   private:
      void buffered_block(const byte input[], size_t input_length);
      void buffered_final(const byte input[], size_t input_length);

      void write(const byte input[], size_t input_length);
      void end_msg();

      BlockCipher* cipher;
      const BlockCipherModePaddingMethod* padder;
      SecureVector<byte> state;
   };

/**
* CBC Decryption
*/
class BOTAN_DLL CBC_Decryption : public Keyed_Filter,
                                 private Buffered_Filter
   {
   public:
      std::string name() const;

      void set_iv(const InitializationVector& iv);

      void set_key(const SymmetricKey& key) { cipher->set_key(key); }

      bool valid_keylength(size_t key_len) const
         { return cipher->valid_keylength(key_len); }

      bool valid_iv_length(size_t iv_len) const
         { return (iv_len == cipher->block_size()); }

      CBC_Decryption(BlockCipher* cipher,
                     BlockCipherModePaddingMethod* padding);

      CBC_Decryption(BlockCipher* cipher,
                     BlockCipherModePaddingMethod* padding,
                     const SymmetricKey& key,
                     const InitializationVector& iv);

      ~CBC_Decryption() { delete cipher; delete padder; }
   private:
      void buffered_block(const byte input[], size_t input_length);
      void buffered_final(const byte input[], size_t input_length);

      void write(const byte[], size_t);
      void end_msg();

      BlockCipher* cipher;
      const BlockCipherModePaddingMethod* padder;
      SecureVector<byte> state, temp;
   };

}

#endif
