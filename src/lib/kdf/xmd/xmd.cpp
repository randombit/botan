/*
* (C) 2019,2020,2021,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/xmd.h>

#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/internal/fmt.h>
#include <vector>

namespace Botan {

void expand_message_xmd(std::string_view hash_fn,
                        std::span<uint8_t> output,
                        std::span<const uint8_t> input,
                        std::span<const uint8_t> domain_sep) {
   if(domain_sep.size() > 0xFF) {
      // RFC 9380 has a specification for handling this
      throw Not_Implemented("XMD does not currently implement oversize DST handling");
   }

   const uint8_t domain_sep_len = static_cast<uint8_t>(domain_sep.size());

   auto hash = HashFunction::create_or_throw(hash_fn);
   const size_t block_size = hash->hash_block_size();
   if(block_size == 0) {
      throw Invalid_Argument(fmt("expand_message_xmd cannot be used with {}", hash_fn));
   }

   const size_t hash_output_size = hash->output_length();
   if(output.size() > 255 * hash_output_size || output.size() > 0xFFFF) {
      throw Invalid_Argument("expand_message_xmd requested output length too long");
   }

   // Compute b_0 = H(msg_prime) = H(Z_pad || msg || l_i_b_str || 0x00 || DST_prime)

   hash->update(std::vector<uint8_t>(block_size));
   hash->update(input);
   hash->update_be(static_cast<uint16_t>(output.size()));
   hash->update(0x00);
   hash->update(domain_sep);
   hash->update(domain_sep_len);

   const secure_vector<uint8_t> b_0 = hash->final();

   // Compute b_1 = H(b_0 || 0x01 || DST_prime)

   hash->update(b_0);
   hash->update(0x01);
   hash->update(domain_sep);
   hash->update(domain_sep_len);

   secure_vector<uint8_t> b_i = hash->final();

   uint8_t cnt = 2;
   for(;;) {
      const size_t produced = std::min(output.size(), hash_output_size);

      copy_mem(&output[0], b_i.data(), produced);
      output = output.subspan(produced);

      if(output.empty()) {
         break;
      }

      // Now compute the next b_i if needed

      b_i ^= b_0;
      hash->update(b_i);
      hash->update(cnt);
      hash->update(domain_sep);
      hash->update(domain_sep_len);
      hash->final(b_i);
      cnt += 1;
   }
}

}  // namespace Botan
