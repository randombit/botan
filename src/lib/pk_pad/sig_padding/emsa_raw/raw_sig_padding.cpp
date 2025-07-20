/*
* (C) 1999-2007,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/raw_sig_padding.h>

#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/fmt.h>

namespace Botan {

std::string SignRawBytes::name() const {
   if(m_expected_size > 0) {
      return fmt("Raw({})", m_expected_size);
   }
   return "Raw";
}

void SignRawBytes::update(const uint8_t input[], size_t length) {
   // The input is just accumulated into the buffer
   m_message += std::make_pair(input, length);
}

std::vector<uint8_t> SignRawBytes::raw_data() {
   /*
   * Return the provided data. If a specific length was indicated (eg for a prehash),
   * check that.
   */

   if(m_expected_size > 0 && m_message.size() != m_expected_size) {
      throw Invalid_Argument(
         fmt("SignRawBytes was configured to use a {} byte hash but instead was used for a {} byte hash",
             m_expected_size,
             m_message.size()));
   }

   std::vector<uint8_t> output;
   std::swap(m_message, output);
   return output;
}

std::vector<uint8_t> SignRawBytes::encoding_of(std::span<const uint8_t> msg,
                                               size_t /*output_bits*/,
                                               RandomNumberGenerator& /*rng*/) {
   if(m_expected_size > 0 && msg.size() != m_expected_size) {
      throw Invalid_Argument(
         fmt("SignRawBytes was configured to use a {} byte hash but instead was used for a {} byte hash",
             m_expected_size,
             msg.size()));
   }

   return std::vector<uint8_t>(msg.begin(), msg.end());
}

bool SignRawBytes::verify(std::span<const uint8_t> coded, std::span<const uint8_t> raw, size_t /*key_bits*/) {
   if(m_expected_size > 0 && raw.size() != m_expected_size) {
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
