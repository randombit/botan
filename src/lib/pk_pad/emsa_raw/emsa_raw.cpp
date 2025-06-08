/*
* EMSA-Raw
* (C) 1999-2007,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/emsa_raw.h>

#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/fmt.h>

namespace Botan {

std::string EMSA_Raw::name() const {
   if(m_expected_size > 0) {
      return fmt("Raw({})", m_expected_size);
   }
   return "Raw";
}

/*
* EMSA-Raw Encode Operation
*/
void EMSA_Raw::update(const uint8_t input[], size_t length) {
   m_message += std::make_pair(input, length);
}

/*
* Return the raw (unencoded) data
*/
std::vector<uint8_t> EMSA_Raw::raw_data() {
   if(m_expected_size && m_message.size() != m_expected_size) {
      throw Invalid_Argument(
         fmt("EMSA_Raw was configured to use a {} byte hash but instead was used for a {} byte hash",
             m_expected_size,
             m_message.size()));
   }

   std::vector<uint8_t> output;
   std::swap(m_message, output);
   return output;
}

/*
* EMSA-Raw Encode Operation
*/
std::vector<uint8_t> EMSA_Raw::encoding_of(std::span<const uint8_t> msg,
                                           size_t /*output_bits*/,
                                           RandomNumberGenerator& /*rng*/) {
   if(m_expected_size && msg.size() != m_expected_size) {
      throw Invalid_Argument(
         fmt("EMSA_Raw was configured to use a {} byte hash but instead was used for a {} byte hash",
             m_expected_size,
             msg.size()));
   }

   return std::vector<uint8_t>(msg.begin(), msg.end());
}

/*
* EMSA-Raw Verify Operation
*/
bool EMSA_Raw::verify(std::span<const uint8_t> coded, std::span<const uint8_t> raw, size_t /*key_bits*/) {
   if(m_expected_size && raw.size() != m_expected_size) {
      return false;
   }

   if(raw.size() > coded.size()) {
      // handle zero padding differences
      const size_t expected_lz = raw.size() - coded.size();
      auto zeros_ok = CT::all_zeros(raw.data(), expected_lz);
      auto contents_ok = CT::is_equal(coded.data(), raw.data() + expected_lz, coded.size());
      return (zeros_ok & contents_ok).as_bool();
   }

   return constant_time_compare(coded, raw);
}

}  // namespace Botan
