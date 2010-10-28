/*
* OFB Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_OUTPUT_FEEDBACK_MODE_H__
#define BOTAN_OUTPUT_FEEDBACK_MODE_H__

#include <botan/stream_cipher.h>
#include <botan/block_cipher.h>

namespace Botan {

/**
* Output Feedback Mode
*/
class BOTAN_DLL OFB : public StreamCipher
   {
   public:
      void cipher(const byte in[], byte out[], size_t length);

      void set_iv(const byte iv[], size_t iv_len);

      bool valid_iv_length(size_t iv_len) const
         { return (iv_len <= permutation->block_size()); }

      Key_Length_Specification key_spec() const
         {
         return permutation->key_spec();
         }

      std::string name() const;

      OFB* clone() const
         { return new OFB(permutation->clone()); }

      void clear();

      /**
      * @param cipher the underlying block cipher to use
      */
      OFB(BlockCipher* cipher);
      ~OFB();
   private:
      void key_schedule(const byte key[], size_t key_len);

      BlockCipher* permutation;
      SecureVector<byte> buffer;
      size_t position;
   };

}

#endif
