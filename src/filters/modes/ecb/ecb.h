/*
* ECB Mode
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ECB_H__
#define BOTAN_ECB_H__

#include <botan/block_cipher.h>
#include <botan/mode_pad.h>
#include <botan/key_filt.h>
#include <botan/buf_filt.h>

namespace Botan {

/**
* ECB Encryption
*/
class BOTAN_DLL ECB_Encryption : public Keyed_Filter,
                                 private Buffered_Filter
   {
   public:
      std::string name() const;

      void set_key(const SymmetricKey& key) { cipher->set_key(key); }

      Key_Length_Specification key_spec() const override { return cipher->key_spec(); }

      ECB_Encryption(BlockCipher* ciph,
                     BlockCipherModePaddingMethod* pad);

      ECB_Encryption(BlockCipher* ciph,
                     BlockCipherModePaddingMethod* pad,
                     const SymmetricKey& key);

      ~ECB_Encryption();
   private:
      void buffered_block(const byte input[], size_t input_length);
      void buffered_final(const byte input[], size_t input_length);

      void write(const byte input[], size_t input_length);
      void end_msg();

      BlockCipher* cipher;
      BlockCipherModePaddingMethod* padder;
      secure_vector<byte> temp;
   };

/**
* ECB Decryption
*/
class BOTAN_DLL ECB_Decryption : public Keyed_Filter,
                                 public Buffered_Filter
   {
   public:
      std::string name() const;

      void set_key(const SymmetricKey& key) { cipher->set_key(key); }

      Key_Length_Specification key_spec() const override { return cipher->key_spec(); }

      ECB_Decryption(BlockCipher* ciph,
                     BlockCipherModePaddingMethod* pad);

      ECB_Decryption(BlockCipher* ciph,
                     BlockCipherModePaddingMethod* pad,
                     const SymmetricKey& key);

      ~ECB_Decryption();
   private:
      void buffered_block(const byte input[], size_t input_length);
      void buffered_final(const byte input[], size_t input_length);

      void write(const byte input[], size_t input_length);
      void end_msg();

      BlockCipher* cipher;
      BlockCipherModePaddingMethod* padder;
      secure_vector<byte> temp;
   };

}

#endif
