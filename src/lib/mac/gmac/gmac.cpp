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

namespace Botan {

GMAC::GMAC(std::unique_ptr<BlockCipher> cipher) :
      m_cipher(std::move(cipher)), m_ghash(std::make_unique<GHASH>()), m_H(GCM_BS), m_initialized(false) {}

void GMAC::clear() {
   m_cipher->clear();
   m_ghash->clear();
   zeroise(m_H);
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
   m_ghash->update_associated_data(input);
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
      m_ghash->nonce_hash(y0, nonce);
   }

   secure_vector<uint8_t> m_enc_y0(GCM_BS);
   m_cipher->encrypt(y0.data(), m_enc_y0.data());
   m_ghash->start(m_enc_y0);
   m_initialized = true;
}

void GMAC::final_result(std::span<uint8_t> mac) {
   // This ensures the GMAC computation has been initialized with a fresh
   // nonce. The aim of this check is to prevent developers from re-using
   // nonces (and potential nonce-reuse attacks).
   if(m_initialized == false) {
      throw Invalid_State("GMAC was not used with a fresh nonce");
   }

   m_ghash->final(mac.first(output_length()));
   m_ghash->set_key(m_H);
}

std::unique_ptr<MessageAuthenticationCode> GMAC::new_object() const {
   return std::make_unique<GMAC>(m_cipher->new_object());
}
}  // namespace Botan
