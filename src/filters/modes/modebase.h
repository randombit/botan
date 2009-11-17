/*
* Block Cipher Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MODEBASE_H__
#define BOTAN_MODEBASE_H__

#include <botan/key_filt.h>
#include <botan/block_cipher.h>

namespace Botan {

/**
* This class represents an abstract block cipher mode
*/
class BOTAN_DLL BlockCipherMode : public Keyed_Filter
   {
   public:
      std::string name() const;

      void set_iv(const InitializationVector&);
      void set_key(const SymmetricKey& key) { cipher->set_key(key); }

      bool valid_keylength(u32bit key_len) const
         { return cipher->valid_keylength(key_len); }

      BlockCipherMode(BlockCipher*, const std::string&,
                      u32bit, u32bit = 0, u32bit = 1);

      virtual ~BlockCipherMode() { delete cipher; }
   protected:
      const u32bit BLOCK_SIZE, BUFFER_SIZE, IV_METHOD;
      const std::string mode_name;
      BlockCipher* cipher;
      SecureVector<byte> buffer, state;
      u32bit position;
   };

}

#endif
