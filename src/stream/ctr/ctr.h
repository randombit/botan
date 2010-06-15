/*
* CTR-BE Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CTR_BE_H__
#define BOTAN_CTR_BE_H__

#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>

namespace Botan {

/**
* CTR-BE (Counter mode, big-endian)
*/
class BOTAN_DLL CTR_BE : public StreamCipher
   {
   public:
      void cipher(const byte in[], byte out[], u32bit length);

      void set_iv(const byte iv[], u32bit iv_len);

      bool valid_iv_length(u32bit iv_len) const
         { return (iv_len <= permutation->BLOCK_SIZE); }

      std::string name() const;

      CTR_BE* clone() const
         { return new CTR_BE(permutation->clone()); }

      void clear();

      CTR_BE(BlockCipher*);
      ~CTR_BE();
   private:
      void key_schedule(const byte key[], u32bit key_len);
      void increment_counter();

      BlockCipher* permutation;
      SecureVector<byte> counter, buffer;
      u32bit position;
   };

}

#endif
