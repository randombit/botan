/*
* SEED
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SEED_H__
#define BOTAN_SEED_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* SEED, a Korean block cipher
*/
class BOTAN_DLL SEED final : public Block_Cipher_Fixed_Params<16, 16>
   {
   public:
      void encrypt_n(const byte in[], byte out[], size_t blocks) const override;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const override;

      void clear() override;
      std::string name() const override { return "SEED"; }
      BlockCipher* clone() const override { return new SEED; }
   private:
      void key_schedule(const byte[], size_t) override;

      secure_vector<u32bit> m_K;
   };

}

#endif
