/*
 * GMAC
 * (C) 2016 Matthias Gierlings, René Korthaus
 * (C) 2017 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/gmac.h>
#include <botan/ghash.h>
#include <botan/exceptn.h>
#include <botan/block_cipher.h>

namespace Botan {

GMAC::GMAC(BlockCipher* cipher) :
   m_cipher(cipher),
   m_ghash(new GHASH),
   m_aad_buf(GCM_BS),
   m_aad_buf_pos(0),
   m_initialized(false)
   {
   }

void GMAC::clear()
   {
   m_cipher->clear();
   m_ghash->clear();
   zeroise(m_aad_buf);
   m_aad_buf_pos = 0;
   m_initialized = false;
   }

GMAC::~GMAC() { /* for unique_ptr */ }

Key_Length_Specification GMAC::key_spec() const
   {
   return m_cipher->key_spec();
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
   if(m_aad_buf_pos > 0)
      {
      const size_t taking = std::min(GCM_BS - m_aad_buf_pos, size);
      copy_mem(&m_aad_buf[m_aad_buf_pos], input, taking);
      m_aad_buf_pos += taking;
      input += taking;
      size -= taking;

      if(m_aad_buf_pos == GCM_BS)
         {
         m_ghash->update_associated_data(m_aad_buf.data(), GCM_BS);
         m_aad_buf_pos = 0;
         }
      }

   const size_t left_over = size % GCM_BS;
   const size_t full_blocks = size - left_over;
   m_ghash->update_associated_data(input, full_blocks);
   input += full_blocks;

   if(left_over > 0)
      {
      copy_mem(&m_aad_buf[m_aad_buf_pos], input, left_over);
      m_aad_buf_pos += left_over;
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
   if(m_aad_buf_pos > 0)
       {
       m_ghash->update_associated_data(m_aad_buf.data(), m_aad_buf_pos);
       }

   m_ghash->final(mac, output_length());
   clear();
   }

MessageAuthenticationCode* GMAC::clone() const
   {
   return new GMAC(m_cipher->clone());
   }
}
