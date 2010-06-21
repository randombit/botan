/*
* Noekeon
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_NOEKEON_H__
#define BOTAN_NOEKEON_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* Noekeon
*/
class BOTAN_DLL Noekeon : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;

      void clear();
      std::string name() const { return "Noekeon"; }
      BlockCipher* clone() const { return new Noekeon; }

      Noekeon() : BlockCipher(16, 16) {}
   protected:
      /**
      * The Noekeon round constants
      */
      static const byte RC[17];

      /**
      * @return const reference to encryption subkeys
      */
      const SecureVector<u32bit, 4>& get_EK() const { return EK; }

      /**
      * @return const reference to decryption subkeys
      */
      const SecureVector<u32bit, 4>& get_DK() const { return DK; }

   private:
      void key_schedule(const byte[], u32bit);
      SecureVector<u32bit, 4> EK, DK;
   };

}

#endif
