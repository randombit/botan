/*
* IDEA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_IDEA_H__
#define BOTAN_IDEA_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* IDEA
*/
class BOTAN_DLL IDEA : public Block_Cipher_Fixed_Params<8, 16>
   {
   public:
      void encrypt_n(const byte in[], byte out[], size_t blocks) const;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const;

      void clear() { zeroise(EK); zeroise(DK); }
      std::string name() const { return "IDEA"; }
      BlockCipher* clone() const { return new IDEA; }

      IDEA() : EK(52), DK(52) {}
   protected:
      /**
      * @return const reference to encryption subkeys
      */
      const SecureVector<u16bit>& get_EK() const { return EK; }

      /**
      * @return const reference to decryption subkeys
      */
      const SecureVector<u16bit>& get_DK() const { return DK; }

   private:
      void key_schedule(const byte[], size_t);
      SecureVector<u16bit> EK, DK;
   };

}

#endif
