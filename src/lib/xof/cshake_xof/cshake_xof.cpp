/*
 * cSHAKE-128 and cSHAKE-256 as XOFs
 *
 * (C) 2016-2023 Jack Lloyd
 *     2022-2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/cshake_xof.h>

#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/keccak_helpers.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/mem_utils.h>

namespace Botan {

namespace {

constexpr auto select_cshake_xof_permutation(size_t capacity) {
   switch(capacity) {
      case 256:
         return Keccak_Permutation({.capacity_bits = 256, .padding = KeccakPadding::cshake()});
      case 512:
         return Keccak_Permutation({.capacity_bits = 512, .padding = KeccakPadding::cshake()});
      default:
         throw Botan::Invalid_Argument("cSHAKE_XOF: Unsupported capacity");
   }
}

}  // namespace

cSHAKE_XOF::cSHAKE_XOF(size_t capacity, std::vector<uint8_t> function_name) :
      m_keccak(select_cshake_xof_permutation(capacity)),
      m_function_name(std::move(function_name)),
      m_output_generated(false) {
   BOTAN_ASSERT_NOMSG(capacity == 256 || capacity == 512);
}

cSHAKE_XOF::cSHAKE_XOF(size_t capacity, std::span<const uint8_t> function_name) :
      cSHAKE_XOF(capacity, std::vector<uint8_t>{function_name.begin(), function_name.end()}) {}

cSHAKE_XOF::cSHAKE_XOF(size_t capacity, std::string_view function_name) :
      cSHAKE_XOF(capacity, as_span_of_bytes(function_name)) {}

void cSHAKE_XOF::reset() {
   m_keccak = select_cshake_xof_permutation(m_keccak.bit_capacity());
   m_output_generated = false;
}

std::string cSHAKE_XOF::provider() const {
   return m_keccak.provider();
}

size_t cSHAKE_XOF::block_size() const {
   return m_keccak.byte_rate();
}

bool cSHAKE_XOF::valid_salt_length(size_t salt_length) const {
   // NIST SP.800-185 Section 3.2
   //     When N and S are both empty strings, cSHAKE(X, L, N, S) is equivalent to
   //     SHAKE as defined in FIPS 202.
   //
   // We don't implement the fallback case where N and S are empty. Hence, if
   // the function name N was defined as 'empty', a salt must be provided.
   return m_function_name.size() + salt_length > 0;
}

void cSHAKE_XOF::start_msg(std::span<const uint8_t> salt, std::span<const uint8_t> key) {
   BOTAN_STATE_CHECK(!m_output_generated);
   BOTAN_ASSERT_NOMSG(key.empty());
   keccak_absorb_padded_strings_encoding(*this, block_size(), m_function_name, salt);
}

void cSHAKE_XOF::add_data(std::span<const uint8_t> input) {
   BOTAN_STATE_CHECK(!m_output_generated);
   m_keccak.absorb(input);
}

void cSHAKE_XOF::generate_bytes(std::span<uint8_t> output) {
   if(!m_output_generated) {
      m_output_generated = true;
      m_keccak.finish();
   }

   m_keccak.squeeze(output);
}

}  // namespace Botan
