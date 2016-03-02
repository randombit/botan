/*
* X9.42 PRF
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ANSI_X942_PRF_H__
#define BOTAN_ANSI_X942_PRF_H__

#include <botan/kdf.h>

namespace Botan {

/**
* PRF from ANSI X9.42
*/
class BOTAN_DLL X942_PRF final : public KDF
   {
   public:
      std::string name() const override { return "X942_PRF(" + m_key_wrap_oid + ")"; }

      KDF* clone() const override { return new X942_PRF(m_key_wrap_oid); }

      size_t kdf(byte key[], size_t key_len,
                 const byte secret[], size_t secret_len,
                 const byte salt[], size_t salt_len) const override;

      explicit X942_PRF(const std::string& oid);
   private:
      std::string m_key_wrap_oid;
   };

}

#endif
