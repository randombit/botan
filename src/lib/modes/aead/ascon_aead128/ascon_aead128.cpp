/*
* Ascon-AEAD128 AEAD
* (C) 2025 Jack Lloyd
*     2025 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ascon_aead128.h>

#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>

namespace Botan {

namespace {

template <size_t N>
constexpr auto as_array_of_uint64(std::span<const uint8_t> in) {
   BOTAN_DEBUG_ASSERT(in.size() == N);
   return load_le<std::array<uint64_t, N>>(in.first<N * 8>());
}

// NIST SP.800-232 Appendix B (Table 13)
constexpr Ascon_p initial_state_of_ascon_aead_permutation({
   .init_and_final_rounds = 12,
   .processing_rounds = 8,
   .bit_rate = 128,
   .initial_state = {},
});

// NIST SP.800-232 Section 5.1
constexpr uint64_t ascon_aead_128_iv = 0x00001000808c0001;

// NIST SP.800-232 Appendix A.2
constexpr uint64_t ascon_aead_128_domain_sep = 0x8000000000000000;

}  // namespace

Ascon_AEAD128_Mode::Ascon_AEAD128_Mode() : m_ascon_p(initial_state_of_ascon_aead_permutation) {}

void Ascon_AEAD128_Mode::clear() {
   m_key.reset();
   m_ascon_p = initial_state_of_ascon_aead_permutation;
   m_ad.clear();
   m_ascon_state_with_ad.reset();
}

void Ascon_AEAD128_Mode::reset() {
   if(has_nonce_and_ad()) {
      BOTAN_ASSERT_NOMSG(has_keying_material());
      m_ascon_p = *m_ascon_state_with_ad;
   } else {
      clear();
   }
}

void Ascon_AEAD128_Mode::set_associated_data_n(size_t, std::span<const uint8_t> ad) {
   BOTAN_STATE_CHECK(has_keying_material());
   m_ad.assign(ad.begin(), ad.end());
}

void Ascon_AEAD128_Mode::start_msg(const uint8_t nonce[], size_t nonce_len) {
   BOTAN_ARG_CHECK(valid_nonce_length(nonce_len), "Invalid nonce length in Ascon-AEAD128");
   BOTAN_STATE_CHECK(has_keying_material());

   m_ascon_p.state() = concat(std::array{ascon_aead_128_iv}, *m_key, as_array_of_uint64<2>({nonce, nonce_len}));
   m_ascon_p.permute();
   m_ascon_p.state()[3] ^= (*m_key)[0];
   m_ascon_p.state()[4] ^= (*m_key)[1];

   m_ascon_p.absorb(m_ad);
   m_ascon_p.finish();
   m_ascon_p.state()[4] ^= ascon_aead_128_domain_sep;

   m_ascon_state_with_ad = m_ascon_p;
   m_ad.clear();
}

void Ascon_AEAD128_Mode::key_schedule(std::span<const uint8_t> key) {
   m_key = as_array_of_uint64<2>(key);
}

size_t Ascon_AEAD128_Mode::process_msg(uint8_t buf[], size_t size) {
   BOTAN_STATE_CHECK(has_nonce_and_ad());
   m_ascon_p.percolate({buf, size});
   return size;
}

void Ascon_AEAD128_Encryption::finish_msg(secure_vector<uint8_t>& final_block, size_t offset) {
   BOTAN_STATE_CHECK(has_nonce_and_ad());

   m_ascon_p.percolate(std::span{final_block}.subspan(offset));
   m_ascon_p.state()[2] ^= (*m_key)[0];
   m_ascon_p.state()[3] ^= (*m_key)[1];
   m_ascon_p.finish();
   m_ascon_p.permute();

   const auto tag = store_le(m_ascon_p.state()[3], m_ascon_p.state()[4]);
   final_block.insert(final_block.end(), tag.begin(), tag.end());
}

void Ascon_AEAD128_Decryption::finish_msg(secure_vector<uint8_t>& final_block, size_t offset) {
   BOTAN_STATE_CHECK(has_nonce_and_ad());

   const auto final_block_at_offset = std::span{final_block}.subspan(offset);
   const auto final_ciphertext_block = std::span{final_block}.first(final_block_at_offset.size() - tag_size());
   const auto expected_tag = std::span{final_block}.last(tag_size());

   m_ascon_p.percolate(final_ciphertext_block);
   m_ascon_p.state()[2] ^= (*m_key)[0];
   m_ascon_p.state()[3] ^= (*m_key)[1];
   m_ascon_p.finish();
   m_ascon_p.permute();

   const auto computed_tag = store_le(m_ascon_p.state()[3], m_ascon_p.state()[4]);
   if(!constant_time_compare(computed_tag, expected_tag)) {
      throw Invalid_Authentication_Tag("Ascon-AEAD128 tag check failed");
   }

   final_block.resize(offset + final_ciphertext_block.size());
}

}  // namespace Botan
