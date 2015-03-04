/*
* HKDF
* (C) 2013,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/kdf_utils.h>
#include <botan/hkdf.h>

namespace Botan {

BOTAN_REGISTER_NAMED_T(KDF, "HKDF", HKDF, HKDF::make);

HKDF* HKDF::make(const Spec& spec)
   {
   if(auto mac = get_mac(spec.arg(0)))
      return new HKDF(mac);

   if(auto mac = get_mac("HMAC(" + spec.arg(0) + ")"))
      return new HKDF(mac);

   return nullptr;
   }

size_t HKDF::kdf(byte out[], size_t out_len,
                 const byte secret[], size_t secret_len,
                 const byte salt[], size_t salt_len) const
   {
   m_prf->set_key(secret, secret_len);

   byte counter = 1;
   secure_vector<byte> h;
   size_t offset = 0;

   while(offset != out_len && counter != 0)
      {
      m_prf->update(h);
      m_prf->update(salt, salt_len);
      m_prf->update(counter++);
      m_prf->final(h);

      const size_t written = std::min(h.size(), out_len - offset);
      copy_mem(&out[offset], &h[0], written);
      offset += written;
      }

   return offset;
   }

}
