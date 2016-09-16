/*
* Serpent
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SERPENT_H__
#define BOTAN_SERPENT_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* Serpent is the most conservative of the AES finalists
* http://www.cl.cam.ac.uk/~rja14/serpent.html
*/
class BOTAN_DLL Serpent final : public Block_Cipher_Fixed_Params<16, 16, 32, 8>
   {
   public:
      void encrypt_n(const byte in[], byte out[], size_t blocks) const override;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const override;

      void clear() override;
      std::string provider() const override;
      std::string name() const override { return "Serpent"; }
      BlockCipher* clone() const override { return new Serpent; }

      size_t parallelism() const override { return 4; }

   protected:
#if defined(BOTAN_HAS_SERPENT_SIMD)
      /**
      * Encrypt 4 blocks in parallel using SSE2 or AltiVec
      */
      void simd_encrypt_4(const byte in[64], byte out[64]) const;

      /**
      * Decrypt 4 blocks in parallel using SSE2 or AltiVec
      */
      void simd_decrypt_4(const byte in[64], byte out[64]) const;
#endif

      /**
      * For use by subclasses using SIMD, asm, etc
      * @return const reference to the key schedule
      */
      const secure_vector<u32bit>& get_round_keys() const
         { return m_round_key; }

      /**
      * For use by subclasses that implement the key schedule
      * @param ks is the new key schedule value to set
      */
      void set_round_keys(const u32bit ks[132])
         {
         m_round_key.assign(&ks[0], &ks[132]);
         }

   private:
      void key_schedule(const byte key[], size_t length) override;
      secure_vector<u32bit> m_round_key;
   };

}

#endif
