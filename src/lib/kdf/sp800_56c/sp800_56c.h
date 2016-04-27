/*
* KDF defined in NIST SP 800-56c
* (C) 2016 Kai Michaelis
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SP800_56C_H__
#define BOTAN_SP800_56C_H__

#include <botan/kdf.h>
#include <botan/mac.h>

namespace Botan {

/**
 * NIST SP 800-56C KDF
 */
class BOTAN_DLL SP800_56C : public KDF
   {
   public:
      std::string name() const override { return "SP800-56C(" + m_prf->name() + ")"; }

      KDF* clone() const override { return new SP800_56C(m_prf->clone(), m_exp->clone()); }

      size_t kdf(byte key[], size_t key_len,
                 const byte secret[], size_t secret_len,
                 const byte salt[], size_t salt_len) const override;

      SP800_56C(MessageAuthenticationCode* mac, KDF* exp) : m_prf(mac), m_exp(exp) {}

      static SP800_56C* make(const Spec& spec);
   private:
      std::unique_ptr<MessageAuthenticationCode> m_prf;
      std::unique_ptr<KDF> m_exp;
   };
}

#endif
