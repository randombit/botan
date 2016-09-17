/*
* IDEA
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_IDEA_H__
#define BOTAN_IDEA_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* IDEA
*/
class BOTAN_DLL IDEA final : public Block_Cipher_Fixed_Params<8, 16>
   {
   public:
      void encrypt_n(const byte in[], byte out[], size_t blocks) const override;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const override;

      void clear() override;

      std::string provider() const override;
      std::string name() const override { return "IDEA"; }
      BlockCipher* clone() const override { return new IDEA; }
   private:
#if defined(BOTAN_HAS_IDEA_SSE2)
      void sse2_idea_op_8(const byte in[64], byte out[64], const u16bit EK[52]) const;
#endif

      void key_schedule(const byte[], size_t) override;

      secure_vector<u16bit> m_EK, m_DK;
   };

}

#endif
