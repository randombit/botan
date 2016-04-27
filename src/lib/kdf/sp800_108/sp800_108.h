/*
* KDFs defined in NIST SP 800-108
* (C) 2016 Kai Michaelis
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SP800_108_H__
#define BOTAN_SP800_108_H__

#include <botan/kdf.h>
#include <botan/mac.h>

namespace Botan {

/**
 * NIST SP 800-108 KDF in Counter Mode (5.1)
 */
class BOTAN_DLL SP800_108_Counter : public KDF
   {
   public:
      std::string name() const override { return "SP800-108-Counter(" + m_prf->name() + ")"; }

      KDF* clone() const override { return new SP800_108_Counter(m_prf->clone()); }

      size_t kdf(byte key[], size_t key_len,
                 const byte secret[], size_t secret_len,
                 const byte salt[], size_t salt_len) const override;

      SP800_108_Counter(MessageAuthenticationCode* mac) : m_prf(mac) {}

      static SP800_108_Counter* make(const Spec& spec);
   private:
      std::unique_ptr<MessageAuthenticationCode> m_prf;
   };

/**
 * NIST SP 800-108 KDF in Feedback Mode (5.2)
 */
class BOTAN_DLL SP800_108_Feedback : public KDF
   {
   public:
      std::string name() const override { return "SP800-108-Feedback(" + m_prf->name() + ")"; }

      KDF* clone() const override { return new SP800_108_Feedback(m_prf->clone()); }

      size_t kdf(byte key[], size_t key_len,
                 const byte secret[], size_t secret_len,
                 const byte salt[], size_t salt_len) const override;

      SP800_108_Feedback(MessageAuthenticationCode* mac) : m_prf(mac) {}

      static SP800_108_Feedback* make(const Spec& spec);
   private:
      std::unique_ptr<MessageAuthenticationCode> m_prf;
   };

/**
 * NIST SP 800-108 KDF in Double Pipeline Mode (5.3)
 */
class BOTAN_DLL SP800_108_Pipeline : public KDF
   {
   public:
      std::string name() const override { return "SP800-108-Pipeline(" + m_prf->name() + ")"; }

      KDF* clone() const override { return new SP800_108_Pipeline(m_prf->clone()); }

      size_t kdf(byte key[], size_t key_len,
                 const byte secret[], size_t secret_len,
                 const byte salt[], size_t salt_len) const override;

      SP800_108_Pipeline(MessageAuthenticationCode* mac) : m_prf(mac) {}

      static SP800_108_Pipeline* make(const Spec& spec);
   private:
      std::unique_ptr<MessageAuthenticationCode> m_prf;
   };

}

#endif
