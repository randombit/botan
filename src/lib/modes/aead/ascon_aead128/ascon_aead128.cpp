/*
* Ascon-AEAD128 AEAD
* (C) 2025 Jack Lloyd
*     2025 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ascon_aead128.h>

#include <botan/exceptn.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/loadstor.h>

namespace Botan {

namespace {

constexpr void xor2x64(std::span<uint64_t, 2> lhs, std::span<const uint64_t, 2> rhs) {
   lhs[0] ^= rhs[0];
   lhs[1] ^= rhs[1];
}

template <size_t N>
constexpr auto as_array_of_uint64(std::span<const uint8_t> in) {
   BOTAN_DEBUG_ASSERT(in.size() == N * sizeof(uint64_t));
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
   m_ad.clear();
   reset();
}

void Ascon_AEAD128_Mode::reset() {
   m_ascon_p = initial_state_of_ascon_aead_permutation;
   m_started = false;
   m_has_nonce = false;
}

void Ascon_AEAD128_Mode::key_schedule(std::span<const uint8_t> key) {
   clear();
   m_key = as_array_of_uint64<2>(key);
}

void Ascon_AEAD128_Mode::set_associated_data_n(size_t idx, std::span<const uint8_t> ad) {
   BOTAN_ARG_CHECK(idx == 0, "Ascon-AEAD128: cannot handle non-zero index in set_associated_data_n");
   m_ad.assign(ad.begin(), ad.end());
}

void Ascon_AEAD128_Mode::start_msg(const uint8_t nonce[], size_t nonce_len) {
   BOTAN_ARG_CHECK(valid_nonce_length(nonce_len), "Invalid nonce length in Ascon-AEAD128");

   BOTAN_STATE_CHECK(has_keying_material());
   BOTAN_STATE_CHECK(!m_started);

   m_ascon_p.state() = concat(std::array{ascon_aead_128_iv}, *m_key, as_array_of_uint64<2>({nonce, nonce_len}));
   m_ascon_p.initial_permute();
   xor2x64(m_ascon_p.range_of_state<3, 2>(), *m_key);

   m_has_nonce = true;
}

void Ascon_AEAD128_Mode::maybe_absorb_associated_data() {
   BOTAN_DEBUG_ASSERT(has_keying_material());
   BOTAN_DEBUG_ASSERT(m_has_nonce);

   if(!m_started) {
      if(!m_ad.empty()) {
         m_ascon_p.absorb(m_ad);
         m_ascon_p.intermediate_finish();
      }
      m_ascon_p.state()[4] ^= ascon_aead_128_domain_sep;

      m_started = true;
   }
}

std::array<uint8_t, 16> Ascon_AEAD128_Mode::calculate_tag_and_finish() {
   BOTAN_DEBUG_ASSERT(m_started);

   xor2x64(m_ascon_p.range_of_state<2, 2>(), *m_key);
   m_ascon_p.finish();
   xor2x64(m_ascon_p.range_of_state<3, 2>(), *m_key);

   auto tag = store_le(m_ascon_p.range_of_state<3, 2>());

   reset();
   return tag;
}

size_t Ascon_AEAD128_Encryption::process_msg(uint8_t buf[], size_t size) {
   BOTAN_STATE_CHECK(has_keying_material());
   BOTAN_STATE_CHECK(m_has_nonce);

   maybe_absorb_associated_data();
   m_ascon_p.percolate_in({buf, size});
   return size;
}

void Ascon_AEAD128_Encryption::finish_msg(secure_vector<uint8_t>& final_block, size_t offset) {
   BOTAN_STATE_CHECK(has_keying_material());

   const auto final_block_at_offset = std::span{final_block}.subspan(offset);
   process_msg(final_block_at_offset.data(), final_block_at_offset.size());
   const auto tag = calculate_tag_and_finish();
   final_block.insert(final_block.end(), tag.begin(), tag.end());
}

size_t Ascon_AEAD128_Decryption::process_msg(uint8_t buf[], size_t size) {
   BOTAN_STATE_CHECK(has_keying_material());
   BOTAN_STATE_CHECK(m_has_nonce);

   maybe_absorb_associated_data();
   m_ascon_p.percolate_out({buf, size});
   return size;
}

void Ascon_AEAD128_Decryption::finish_msg(secure_vector<uint8_t>& final_block, size_t offset) {
   BOTAN_STATE_CHECK(has_keying_material());

   const auto final_block_at_offset = std::span{final_block}.subspan(offset);
   const auto final_ciphertext_block = final_block_at_offset.first(final_block_at_offset.size() - tag_size());
   const auto expected_tag = final_block_at_offset.last(tag_size());

   process_msg(final_ciphertext_block.data(), final_ciphertext_block.size());
   if(!constant_time_compare(calculate_tag_and_finish(), expected_tag)) {
      throw Invalid_Authentication_Tag("Ascon-AEAD128 tag check failed");
   }

   final_block.resize(offset + final_ciphertext_block.size());
}

}  // namespace Botan
