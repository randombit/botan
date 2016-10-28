/*
 * GMAC
 * (C) 2016 Matthias Gierlings, René Korthaus
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/gmac.h>

namespace Botan {

GMAC::GMAC(BlockCipher* cipher)
    : GHASH(),
      m_aad_buf(),
      m_cipher(cipher),
      m_initialized(false)
   {}

void GMAC::clear()
   {
   GHASH::clear();
   m_H.resize(GCM_BS);
   m_H_ad.resize(GCM_BS);
   m_ghash.resize(GCM_BS);
   m_cipher->clear();
   m_aad_buf.clear();
   m_initialized = false;
   }

std::string GMAC::name() const
   {
   return "GMAC(" + m_cipher->name() + ")";
   }

size_t GMAC::output_length() const
   {
   return GCM_BS;
   }

void GMAC::add_data(const byte input[], size_t size)
   {
   m_ad_len += size;

   // buffer partial blocks till we received a full input block
   // or final is called.
   m_aad_buf.insert(m_aad_buf.end(), input, input + size);
   if(m_aad_buf.size() >= GCM_BS)
      {
      // process all complete input blocks.
      ghash_update(m_ghash,
                   m_aad_buf.data(),
                   m_aad_buf.size() - (m_aad_buf.size() % GCM_BS));

      // remove all processed blocks from buffer.
      m_aad_buf.erase(m_aad_buf.begin(),
                      m_aad_buf.end() - (m_aad_buf.size() % GCM_BS));
      }
   }

void GMAC::key_schedule(const byte key[], size_t size)
   {
   clear();
   m_cipher->set_key(key, size);
   m_cipher->encrypt(m_H_ad.data(), m_H.data());
   }

void GMAC::start_msg(const byte nonce[], size_t nonce_len)
   {
   secure_vector<byte> y0(GCM_BS);

   if(nonce_len == 12)
      {
      copy_mem(y0.data(), nonce, nonce_len);
      y0[GCM_BS - 1] = 1;
      }
   else
      {
      ghash_update(y0, nonce, nonce_len);
      add_final_block(y0, 0, nonce_len);
      }

   secure_vector<byte> m_enc_y0(GCM_BS);
   m_cipher->encrypt(y0.data(), m_enc_y0.data());
   GHASH::start(m_enc_y0.data(), m_enc_y0.size());
   m_initialized = true;
   }

void GMAC::final_result(byte mac[])
   {
   // This ensures the GMAC computation has been initialized with a fresh
   // nonce. The aim of this check is to prevent developers from re-using
   // nonces (and potential nonce-reuse attacks).
   BOTAN_ASSERT(m_initialized,
                "The GMAC computation has not been initialized with a fresh "
                "nonce.");
   // process the rest of the aad buffer. Even if it is a partial block only
   // ghash_update will process it properly.
   if(m_aad_buf.size() > 0)
       {
       ghash_update(m_ghash,
                    m_aad_buf.data(),
                    m_aad_buf.size());
       }
   secure_vector<byte> result = GHASH::final();
   std::copy(result.begin(), result.end(), mac);
   clear();
   }

MessageAuthenticationCode* GMAC::clone() const
   {
   return new GMAC(m_cipher->clone());
   }
}
