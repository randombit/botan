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

/*
* OFB Mode
*/
class BOTAN_DLL OFB : public StreamCipher
   {
   public:
      void cipher(const byte in[], byte out[], u32bit length);

      void set_iv(const byte iv[], u32bit iv_len);

      bool valid_iv_length(u32bit iv_len) const
         { return (iv_len <= permutation->BLOCK_SIZE); }

      std::string name() const;

      OFB* clone() const
         { return new OFB(permutation->clone()); }

      void clear() throw();

      OFB(BlockCipher*);
      ~OFB();
   private:
      void key_schedule(const byte key[], u32bit key_len);

      BlockCipher* permutation;
      SecureVector<byte> buffer;
      u32bit position;
   };

}

#endif
