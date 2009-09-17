/*
* CTR Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_COUNTER_MODE_H__
#define BOTAN_COUNTER_MODE_H__

#include <botan/key_filt.h>
#include <botan/block_cipher.h>

namespace Botan {

/*
* CTR-BE Mode
*/
class BOTAN_DLL CTR_BE : public Keyed_Filter
   {
   public:
      std::string name() const;

      void set_iv(const InitializationVector&);

      void set_key(const SymmetricKey& key) { cipher->set_key(key); }

      bool valid_keylength(u32bit key_len) const
         { return cipher->valid_keylength(key_len); }

      CTR_BE(BlockCipher*);
      CTR_BE(BlockCipher*, const SymmetricKey&, const InitializationVector&);

      ~CTR_BE();
   private:
      void write(const byte[], u32bit);
      void increment_counter();

      BlockCipher* cipher;
      SecureVector<byte> counter, enc_buffer;
      u32bit position;
   };

}

#endif
