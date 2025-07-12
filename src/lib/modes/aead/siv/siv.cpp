/*
* SIV Mode Encryption
* (C) 2013,2017 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/siv.h>

#include <botan/block_cipher.h>
#include <botan/mem_ops.h>
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

   if(nonce_len > 0) {
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

std::array<uint8_t, SIV_Mode::tag_length> SIV_Mode::S2V(std::span<const uint8_t> text) {
   const auto BS = block_size();

   const std::vector<uint8_t> zeros(BS);

   secure_vector<uint8_t> V = m_mac->process(zeros);
   BOTAN_DEBUG_ASSERT(V.size() == BS);

   for(size_t i = 0; i != m_ad_macs.size(); ++i) {
      poly_double_n(V.data(), V.size());
      V ^= m_ad_macs[i];
   }

   if(!m_nonce.empty()) {
      poly_double_n(V.data(), V.size());
      V ^= m_nonce;
   }

   if(text.size() < BS) {
      poly_double_n(V.data(), V.size());
      xor_buf(std::span{V}.first(text.size()), text);
      V[text.size()] ^= 0x80;
      m_mac->update(V);
   } else {
      m_mac->update(text.first(text.size() - BS));
      xor_buf(std::span{V}, text.last(BS));
      m_mac->update(V);
   }

   std::array<uint8_t, tag_length> out{};
   m_mac->final(out);
   return out;
}

void SIV_Mode::set_ctr_iv(std::array<uint8_t, SIV_Mode::tag_length> V) {
   V[m_bs - 8] &= 0x7F;
   V[m_bs - 4] &= 0x7F;

   ctr().set_iv(V);
}

size_t SIV_Encryption::finish_msg(std::span<uint8_t> buffer, size_t input_bytes) {
   auto& buffered = msg_buf();
   BOTAN_ASSERT_NOMSG(buffered.size() + input_bytes + tag_length == buffer.size());

   const auto entire_payload = buffer.subspan(tag_length);

   copy_mem(entire_payload.last(input_bytes), buffer.first(input_bytes));
   copy_mem(entire_payload.first(buffered.size()), buffered);

   const auto V = S2V(entire_payload);
   copy_mem(buffer.first<tag_length>(), V);

   if(!entire_payload.empty()) {
      set_ctr_iv(V);
      ctr().cipher1(entire_payload);
   }

   return buffer.size();
}

size_t SIV_Decryption::finish_msg(std::span<uint8_t> buffer, size_t input_bytes) {
   auto& buffered = msg_buf();
   BOTAN_ASSERT_NOMSG(buffered.size() + input_bytes == buffer.size());

   if(!buffered.empty()) {
      copy_mem(buffer.last(input_bytes), buffer.first(input_bytes));
      copy_mem(buffer.first(buffered.size()), buffered);
      buffered.clear();
   }

   const auto V = typecast_copy<std::array<uint8_t, tag_length>>(buffer.first<tag_length>());
   const auto encrypted_payload = buffer.subspan(tag_length);
   const auto plaintext_payload = buffer.first(encrypted_payload.size());
   if(!encrypted_payload.empty()) {
      set_ctr_iv(V);
      ctr().cipher(encrypted_payload, plaintext_payload);
   }

   const auto T = S2V(plaintext_payload);

   if(!CT::is_equal(T.data(), V.data(), T.size()).as_bool()) {
      throw Invalid_Authentication_Tag("SIV tag check failed");
   }

   return plaintext_payload.size();
}

}  // namespace Botan
