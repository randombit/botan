/*
 * GMAC
 * (C) 2016 Matthias Gierlings, René Korthaus
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/gmac.h>

namespace Botan {

GMAC* GMAC::make(const Spec& spec)
   {
   if(spec.arg_count() == 1)
      {
      if(auto bc = BlockCipher::create(spec.arg(0)))
         return new GMAC(bc.release());
      }
   return nullptr;
   }

GMAC::GMAC(BlockCipher* cipher)
    : m_iv(), m_aad(),
      m_gcm(GCM_Encryption(cipher)), m_cipher(cipher->clone())
   {
   }

void GMAC::clear()
   {
   m_gcm.clear();
   zeroise(m_iv);
   zeroise(m_aad);
   }

std::string GMAC::name() const
   {
   return "GMAC(" + m_cipher->name() + ")";
   }

size_t GMAC::output_length() const
   {
   return m_gcm.tag_size();
   }

void GMAC::add_data(const byte input[], size_t length)
   {
   m_aad.insert(m_aad.end(), input, input + length);
   }

void GMAC::start(const std::vector<byte>& nonce)
   {
   m_iv.assign(nonce.begin(), nonce.end());
   }

void GMAC::start(const secure_vector<byte>& nonce)
   {
   m_iv.assign(nonce.begin(), nonce.end());
   }

void GMAC::final_result(byte mac[])
   {
   secure_vector<byte> result;
   m_gcm.set_associated_data(m_aad.data(), m_aad.size());
   m_gcm.start(m_iv);
   m_gcm.finish(result);
   std::copy(result.begin(), result.end(), mac);

   zeroise(m_aad);
   m_aad.clear();
   }

MessageAuthenticationCode* GMAC::clone() const
   {
   return new GMAC(m_cipher->clone());
   }
}
