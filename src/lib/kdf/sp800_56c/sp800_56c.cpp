/*
* KDF defined in NIST SP 800-56c
* (C) 2016 Kai Michaelis
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sp800_108.h>
#include <botan/sp800_56c.h>
#include <botan/hmac.h>

namespace Botan {

SP800_56C* SP800_56C::make(const Spec& spec)
   {
   if(auto exp = SP800_108_Feedback::make(spec))
      {
      if(auto mac = MessageAuthenticationCode::create(spec.arg(0)))
         return new SP800_56C(mac.release(), exp);

      if(auto mac = MessageAuthenticationCode::create("HMAC(" + spec.arg(0) + ")"))
         return new SP800_56C(mac.release(), exp);
      }

   return nullptr;
   }

size_t SP800_56C::kdf(byte key[], size_t key_len,
                      const byte secret[], size_t secret_len,
                      const byte salt[], size_t salt_len,
                      const byte label[], size_t label_len) const
   {
      // Randomness Extraction
      secure_vector< byte > k_dk;

      m_prf->set_key(salt, salt_len);
      m_prf->update(secret, secret_len);
      m_prf->final(k_dk);

      // Key Expansion
      m_exp->kdf(key, key_len, k_dk.data(), k_dk.size(), nullptr, 0, label, label_len);

   return key_len;
   }

}
