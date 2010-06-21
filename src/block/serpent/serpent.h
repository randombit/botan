/*
* Serpent
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SERPENT_H__
#define BOTAN_SERPENT_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* Serpent, an AES finalist
*/
class BOTAN_DLL Serpent : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;

      void clear() { round_key.clear(); }
      std::string name() const { return "Serpent"; }
      BlockCipher* clone() const { return new Serpent; }
      Serpent() : BlockCipher(16, 16, 32, 8) {}
   protected:
      /**
      * For use by subclasses using SIMD, asm, etc
      * @return const reference to the key schedule
      */
      const SecureVector<u32bit, 132>& get_round_keys() const
         { return round_key; }

      /**
      * For use by subclasses that implement the key schedule
      * @param ks is the new key schedule value to set
      */
      void set_round_keys(const u32bit ks[132])
         { round_key.set(ks, 132); }

   private:
      void key_schedule(const byte key[], u32bit length);
      SecureVector<u32bit, 132> round_key;
   };

}

#endif
