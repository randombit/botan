/*
 * GMAC
 * (C) 2016 Matthias Gierlings, René Korthaus
 * (C) 2017 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/gmac.h>

#include <botan/block_cipher.h>
#include <botan/exceptn.h>
#include <botan/internal/fmt.h>
#include <botan/internal/ghash.h>
#include <botan/internal/stl_util.h>

namespace Botan {

GMAC::GMAC(std::unique_ptr<BlockCipher> cipher) :
      m_cipher(std::move(cipher)),
      m_ghash(std::make_unique<GHASH>()),
      m_aad_buf(GCM_BS),
      m_H(GCM_BS),
      m_aad_buf_pos(0),
      m_initialized(false) {}

void GMAC::clear() {
   m_cipher->clear();
   m_ghash->clear();
   zeroise(m_aad_buf);
   zeroise(m_H);
   m_aad_buf_pos = 0;
   m_initialized = false;
}

GMAC::~GMAC() = default;

Key_Length_Specification GMAC::key_spec() const {
   return m_cipher->key_spec();
}

std::string GMAC::name() const {
   return fmt("GMAC({})", m_cipher->name());
}

size_t GMAC::output_length() const {
   return GCM_BS;
}

void GMAC::add_data(std::span<const uint8_t> input) {
   BufferSlicer in(input);

   if(m_aad_buf_pos > 0) {
      const auto part = in.take(std::min(GCM_BS - m_aad_buf_pos, in.remaining()));
      copy_mem(&m_aad_buf[m_aad_buf_pos], part.data(), part.size());
      m_aad_buf_pos += part.size();

      if(m_aad_buf_pos == GCM_BS) {
         m_ghash->update_associated_data(m_aad_buf.data(), GCM_BS);
         m_aad_buf_pos = 0;
      }
   }

   const size_t left_over = in.remaining() % GCM_BS;
   const size_t full_blocks = in.remaining() - left_over;
   m_ghash->update_associated_data(in.take(full_blocks).data(), full_blocks);

   if(!in.empty()) {
      const auto remaining = in.take(in.remaining());
      copy_mem(&m_aad_buf[m_aad_buf_pos], remaining.data(), remaining.size());
      m_aad_buf_pos += remaining.size();
   }
}

bool GMAC::has_keying_material() const {
   return m_cipher->has_keying_material();
}

void GMAC::key_schedule(std::span<const uint8_t> key) {
   clear();
   m_cipher->set_key(key);

   m_cipher->encrypt(m_H);
   m_ghash->set_key(m_H);
}

void GMAC::start_msg(std::span<const uint8_t> nonce) {
   secure_vector<uint8_t> y0(GCM_BS);

   if(nonce.size() == 12) {
      copy_mem(y0.data(), nonce.data(), nonce.size());
      y0[GCM_BS - 1] = 1;
   } else {
      m_ghash->ghash_update(y0, nonce.data(), nonce.size());
      m_ghash->add_final_block(y0, 0, nonce.size());
   }

   secure_vector<uint8_t> m_enc_y0(GCM_BS);
   m_cipher->encrypt(y0.data(), m_enc_y0.data());
   m_ghash->start(m_enc_y0.data(), m_enc_y0.size());
   m_initialized = true;
}

void GMAC::final_result(std::span<uint8_t> mac) {
   // This ensures the GMAC computation has been initialized with a fresh
   // nonce. The aim of this check is to prevent developers from re-using
   // nonces (and potential nonce-reuse attacks).
   if(m_initialized == false) {
      throw Invalid_State("GMAC was not used with a fresh nonce");
   }

   // process the rest of the aad buffer. Even if it is a partial block only
   // ghash_update will process it properly.
   if(m_aad_buf_pos > 0) {
      m_ghash->update_associated_data(m_aad_buf.data(), m_aad_buf_pos);
   }

   m_ghash->final(mac.data(), output_length());
   m_ghash->set_key(m_H);
   m_aad_buf_pos = 0;
}

std::unique_ptr<MessageAuthenticationCode> GMAC::new_object() const {
   return std::make_unique<GMAC>(m_cipher->new_object());
}
}  // namespace Botan
