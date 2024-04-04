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
                        uint8_t output[],
                        size_t output_len,
                        const uint8_t input[],
                        size_t input_len,
                        const uint8_t domain_sep[],
                        size_t domain_sep_len) {
   if(domain_sep_len > 0xFF) {
      throw Invalid_Argument("expand_message_xmd domain seperator too long");
   }

   auto hash = HashFunction::create_or_throw(hash_fn);
   const size_t block_size = hash->hash_block_size();
   if(block_size == 0) {
      throw Invalid_Argument(fmt("expand_message_xmd cannot be used with {}", hash_fn));
   }

   const size_t hash_output_size = hash->output_length();
   if(output_len > 255 * hash_output_size || output_len > 0xFFFF) {
      throw Invalid_Argument("expand_message_xmd requested output length too long");
   }

   // Compute b_0 = H(msg_prime) = H(Z_pad || msg || l_i_b_str || 0x00 || DST_prime)

   hash->update(std::vector<uint8_t>(block_size));
   hash->update(input, input_len);
   hash->update_be(static_cast<uint16_t>(output_len));
   hash->update(0x00);
   hash->update(domain_sep, domain_sep_len);
   hash->update(static_cast<uint8_t>(domain_sep_len));

   const secure_vector<uint8_t> b_0 = hash->final();

   // Compute b_1 = H(b_0 || 0x01 || DST_prime)

   hash->update(b_0);
   hash->update(0x01);
   hash->update(domain_sep, domain_sep_len);
   hash->update(static_cast<uint8_t>(domain_sep_len));

   secure_vector<uint8_t> b_i = hash->final();

   uint8_t cnt = 2;
   while(output_len > 0) {
      const size_t produced = std::min(output_len, hash_output_size);

      copy_mem(output, b_i.data(), produced);
      output += produced;
      output_len -= produced;

      // Now compute the next b_i

      b_i ^= b_0;
      hash->update(b_i);
      hash->update(cnt);
      hash->update(domain_sep, domain_sep_len);
      hash->update(static_cast<uint8_t>(domain_sep_len));
      hash->final(b_i.data());
      cnt += 1;
   }
}

}  // namespace Botan
