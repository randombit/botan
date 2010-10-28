/*
* XTEA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_XTEA_H__
#define BOTAN_XTEA_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* XTEA
*/
class BOTAN_DLL XTEA : public Block_Cipher_Fixed_Params<8, 16>
   {
   public:
      void encrypt_n(const byte in[], byte out[], size_t blocks) const;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const;

      void clear() { zeroise(EK); }
      std::string name() const { return "XTEA"; }
      BlockCipher* clone() const { return new XTEA; }

      XTEA() : EK(64) {}
   protected:
      /**
      * @return const reference to the key schedule
      */
      const SecureVector<u32bit>& get_EK() const { return EK; }

   private:
      void key_schedule(const byte[], size_t);
      SecureVector<u32bit> EK;
   };

}

#endif
