/*
 * GMAC
 * (C) 2016 Matthias Gierlings, René Korthaus
 * (C) 2017 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/gmac.h>

namespace Botan {

GMAC::GMAC(BlockCipher* cipher) :
   m_aad_buf(),
   m_cipher(cipher),
   m_ghash(new GHASH),
   m_initialized(false)
   {}

void GMAC::clear()
   {
   m_cipher->clear();
   m_ghash->clear();
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

void GMAC::add_data(const uint8_t input[], size_t size)
   {
   /*
   FIXME this could be much more efficient, and only buffer leftovers
   as needed, instead of inserting everything into the buffer
   */

   // buffer partial blocks till we received a full input block
   // or final is called.
   m_aad_buf.insert(m_aad_buf.end(), input, input + size);
   if(m_aad_buf.size() >= GCM_BS)
      {
      // process all complete input blocks.
      m_ghash->update_associated_data(m_aad_buf.data(),
                                      m_aad_buf.size() - (m_aad_buf.size() % GCM_BS));

      // remove all processed blocks from buffer.
      m_aad_buf.erase(m_aad_buf.begin(),
                      m_aad_buf.end() - (m_aad_buf.size() % GCM_BS));
      }
   }

void GMAC::key_schedule(const uint8_t key[], size_t size)
   {
   clear();
   m_cipher->set_key(key, size);

   secure_vector<uint8_t> H(GCM_BS);
   m_cipher->encrypt(H);
   m_ghash->set_key(H);
   }

void GMAC::start_msg(const uint8_t nonce[], size_t nonce_len)
   {
   secure_vector<uint8_t> y0(GCM_BS);

   if(nonce_len == 12)
      {
      copy_mem(y0.data(), nonce, nonce_len);
      y0[GCM_BS - 1] = 1;
      }
   else
      {
      m_ghash->ghash_update(y0, nonce, nonce_len);
      m_ghash->add_final_block(y0, 0, nonce_len);
      }

   secure_vector<uint8_t> m_enc_y0(GCM_BS);
   m_cipher->encrypt(y0.data(), m_enc_y0.data());
   m_ghash->start(m_enc_y0.data(), m_enc_y0.size());
   m_initialized = true;
   }

void GMAC::final_result(uint8_t mac[])
   {
   // This ensures the GMAC computation has been initialized with a fresh
   // nonce. The aim of this check is to prevent developers from re-using
   // nonces (and potential nonce-reuse attacks).
   if(m_initialized == false)
      throw Invalid_State("GMAC was not used with a fresh nonce");

   // process the rest of the aad buffer. Even if it is a partial block only
   // ghash_update will process it properly.
   if(m_aad_buf.size() > 0)
       {
       m_ghash->update_associated_data(m_aad_buf.data(), m_aad_buf.size());
       }
   secure_vector<uint8_t> result = m_ghash->final();
   copy_mem(mac, result.data(), result.size());
   clear();
   }

MessageAuthenticationCode* GMAC::clone() const
   {
   return new GMAC(m_cipher->clone());
   }
}
