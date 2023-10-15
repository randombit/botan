/*
* SIV Mode Encryption
* (C) 2013,2017 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/siv.h>

#include <botan/block_cipher.h>
#include <botan/internal/cmac.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/ctr.h>
#include <botan/internal/poly_dbl.h>

namespace Botan {

SIV_Mode::SIV_Mode(std::unique_ptr<BlockCipher> cipher) :
      m_name(cipher->name() + "/SIV"),
      m_bs(cipher->block_size()),
      m_ctr(std::make_unique<CTR_BE>(cipher->new_object(), 8)),
      m_mac(std::make_unique<CMAC>(std::move(cipher))) {
   // Not really true but only 128 bit allowed at the moment
   if(m_bs != 16) {
      throw Invalid_Argument("SIV requires a 128 bit block cipher");
   }
}

SIV_Mode::~SIV_Mode() = default;

void SIV_Mode::clear() {
   m_ctr->clear();
   m_mac->clear();
   reset();
}

void SIV_Mode::reset() {
   m_nonce.clear();
   m_msg_buf.clear();
   m_ad_macs.clear();
}

std::string SIV_Mode::name() const {
   return m_name;
}

bool SIV_Mode::valid_nonce_length(size_t /*nonce_len*/) const {
   return true;
}

size_t SIV_Mode::update_granularity() const {
   return 1;
}

size_t SIV_Mode::ideal_granularity() const {
   // Completely arbitrary value:
   return 128;
}

bool SIV_Mode::requires_entire_message() const {
   return true;
}

Key_Length_Specification SIV_Mode::key_spec() const {
   return m_mac->key_spec().multiple(2);
}

bool SIV_Mode::has_keying_material() const {
   return m_ctr->has_keying_material() && m_mac->has_keying_material();
}

void SIV_Mode::key_schedule(std::span<const uint8_t> key) {
   const size_t keylen = key.size() / 2;
   m_mac->set_key(key.first(keylen));
   m_ctr->set_key(key.last(keylen));
   m_ad_macs.clear();
}

size_t SIV_Mode::maximum_associated_data_inputs() const {
   return block_size() * 8 - 2;
}

void SIV_Mode::set_associated_data_n(size_t n, std::span<const uint8_t> ad) {
   const size_t max_ads = maximum_associated_data_inputs();
   if(n > max_ads) {
      throw Invalid_Argument(name() + " allows no more than " + std::to_string(max_ads) + " ADs");
   }

   if(n >= m_ad_macs.size()) {
      m_ad_macs.resize(n + 1);
   }

   m_ad_macs[n] = m_mac->process(ad);
}

void SIV_Mode::start_msg(const uint8_t nonce[], size_t nonce_len) {
   if(!valid_nonce_length(nonce_len)) {
      throw Invalid_IV_Length(name(), nonce_len);
   }

   if(nonce_len) {
      m_nonce = m_mac->process(nonce, nonce_len);
   } else {
      m_nonce.clear();
   }

   m_msg_buf.clear();
}

size_t SIV_Mode::process_msg(uint8_t buf[], size_t sz) {
   // all output is saved for processing in finish
   m_msg_buf.insert(m_msg_buf.end(), buf, buf + sz);
   return 0;
}

secure_vector<uint8_t> SIV_Mode::S2V(const uint8_t* text, size_t text_len) {
   const std::vector<uint8_t> zeros(block_size());

   secure_vector<uint8_t> V = m_mac->process(zeros.data(), zeros.size());

   for(size_t i = 0; i != m_ad_macs.size(); ++i) {
      poly_double_n(V.data(), V.size());
      V ^= m_ad_macs[i];
   }

   if(!m_nonce.empty()) {
      poly_double_n(V.data(), V.size());
      V ^= m_nonce;
   }

   if(text_len < block_size()) {
      poly_double_n(V.data(), V.size());
      xor_buf(V.data(), text, text_len);
      V[text_len] ^= 0x80;
      return m_mac->process(V);
   }

   m_mac->update(text, text_len - block_size());
   xor_buf(V.data(), &text[text_len - block_size()], block_size());
   m_mac->update(V);

   return m_mac->final();
}

void SIV_Mode::set_ctr_iv(secure_vector<uint8_t> V) {
   V[m_bs - 8] &= 0x7F;
   V[m_bs - 4] &= 0x7F;

   ctr().set_iv(V.data(), V.size());
}

void SIV_Encryption::finish_msg(secure_vector<uint8_t>& buffer, size_t offset) {
   BOTAN_ARG_CHECK(buffer.size() >= offset, "Offset is out of range");

   buffer.insert(buffer.begin() + offset, msg_buf().begin(), msg_buf().end());
   msg_buf().clear();

   const secure_vector<uint8_t> V = S2V(buffer.data() + offset, buffer.size() - offset);

   buffer.insert(buffer.begin() + offset, V.begin(), V.end());

   if(buffer.size() != offset + V.size()) {
      set_ctr_iv(V);
      ctr().cipher1(&buffer[offset + V.size()], buffer.size() - offset - V.size());
   }
}

void SIV_Decryption::finish_msg(secure_vector<uint8_t>& buffer, size_t offset) {
   BOTAN_ARG_CHECK(buffer.size() >= offset, "Offset is out of range");

   if(!msg_buf().empty()) {
      buffer.insert(buffer.begin() + offset, msg_buf().begin(), msg_buf().end());
      msg_buf().clear();
   }

   const size_t sz = buffer.size() - offset;

   BOTAN_ARG_CHECK(sz >= tag_size(), "input did not include the tag");

   secure_vector<uint8_t> V(buffer.data() + offset, buffer.data() + offset + block_size());

   if(buffer.size() != offset + V.size()) {
      set_ctr_iv(V);

      ctr().cipher(buffer.data() + offset + V.size(), buffer.data() + offset, buffer.size() - offset - V.size());
   }

   const secure_vector<uint8_t> T = S2V(buffer.data() + offset, buffer.size() - offset - V.size());

   if(!CT::is_equal(T.data(), V.data(), T.size()).as_bool()) {
      throw Invalid_Authentication_Tag("SIV tag check failed");
   }

   buffer.resize(buffer.size() - tag_size());
}

}  // namespace Botan
