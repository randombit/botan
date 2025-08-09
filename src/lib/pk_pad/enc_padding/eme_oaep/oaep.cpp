/*
* OAEP
* (C) 1999-2010,2015,2018,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/oaep.h>

#include <botan/exceptn.h>
#include <botan/rng.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/mgf1.h>
#include <botan/internal/stl_util.h>

namespace Botan {

/*
* OAEP Pad Operation
*/
size_t OAEP::pad(std::span<uint8_t> output,
                 std::span<const uint8_t> input,
                 size_t key_length,
                 RandomNumberGenerator& rng) const {
   key_length /= 8;

   if(input.size() > maximum_input_size(key_length * 8)) {
      throw Invalid_Argument("OAEP: Input is too large");
   }

   const size_t output_size = key_length;

   output = output.first(output_size);  // remainder ignored

   BufferStuffer stuffer(output);

   // We always use a seed len equal to the underlying hash
   rng.randomize(stuffer.next(m_Phash.size()));
   stuffer.append(m_Phash);
   stuffer.append(0x00, stuffer.remaining_capacity() - (1 + input.size()));
   stuffer.append(0x01);
   stuffer.append(input);
   BOTAN_ASSERT_NOMSG(stuffer.full());

   const size_t hlen = m_Phash.size();

   mgf1_mask(*m_mgf1_hash, output.first(hlen), output.subspan(hlen));

   mgf1_mask(*m_mgf1_hash, output.subspan(hlen), output.first(hlen));

   return key_length;
}

/*
* OAEP Unpad Operation
*/
CT::Option<size_t> OAEP::unpad(std::span<uint8_t> output, std::span<const uint8_t> input) const {
   BOTAN_ASSERT_NOMSG(output.size() >= input.size());

   /*
   Must be careful about error messages here; if an attacker can
   distinguish them, it is easy to use the differences as an oracle to
   find the secret key, as described in "A Chosen Ciphertext Attack on
   RSA Optimal Asymmetric Encryption Padding (OAEP) as Standardized in
   PKCS #1 v2.0", James Manger, Crypto 2001

   Also have to be careful about timing attacks! Pointed out by Falko
   Strenzke.

   According to the standard (RFC 3447 Section 7.1.1), the encryptor always
   creates a message as follows:
      i. Concatenate a single octet with hexadecimal value 0x00,
         maskedSeed, and maskedDB to form an encoded message EM of
         length k octets as
            EM = 0x00 || maskedSeed || maskedDB.
   where k is the length of the modulus N.
   Therefore, the first byte should always be zero.
   */

   if(input.empty()) {
      return {};
   }

   auto scope = CT::scoped_poison(input);

   const auto has_leading_0 = CT::Mask<uint8_t>::is_zero(input[0]).as_choice();

   secure_vector<uint8_t> decoded(input.begin() + 1, input.end());
   auto buf = std::span{decoded};

   const size_t hlen = m_Phash.size();

   mgf1_mask(*m_mgf1_hash, buf.subspan(hlen), buf.first(hlen));

   mgf1_mask(*m_mgf1_hash, buf.first(hlen), buf.subspan(hlen));

   auto delim = oaep_find_delim(buf, m_Phash);

   return CT::copy_output(delim.has_value() && has_leading_0, output, buf, delim.value_or(0));
}

CT::Option<size_t> oaep_find_delim(std::span<const uint8_t> input, std::span<const uint8_t> phash) {
   // Too short to be valid, reject immediately
   if(input.size() < 1 + 2 * phash.size()) {
      return {};
   }

   size_t delim_idx = 2 * phash.size();
   CT::Mask<uint8_t> waiting_for_delim = CT::Mask<uint8_t>::set();
   CT::Mask<uint8_t> bad_input_m = CT::Mask<uint8_t>::cleared();

   for(uint8_t ib : input.subspan(2 * phash.size())) {
      const auto zero_m = CT::Mask<uint8_t>::is_zero(ib);
      const auto one_m = CT::Mask<uint8_t>::is_equal(ib, 1);

      const auto add_m = waiting_for_delim & zero_m;

      bad_input_m |= waiting_for_delim & ~(zero_m | one_m);

      delim_idx += add_m.if_set_return(1);

      waiting_for_delim &= zero_m;
   }

   // If we never saw any non-zero byte, then it's not valid input
   bad_input_m |= waiting_for_delim;

   // If the P hash is wrong, then it's not valid
   bad_input_m |= CT::is_not_equal(&input[phash.size()], phash.data(), phash.size());

   delim_idx += 1;

   const auto accept = !(bad_input_m.as_choice());

   return CT::Option(delim_idx, accept);
}

/*
* Return the max input size for a given key size
*/
size_t OAEP::maximum_input_size(size_t keybits) const {
   if(keybits / 8 > 2 * m_Phash.size() + 1) {
      return ((keybits / 8) - 2 * m_Phash.size() - 1);
   } else {
      return 0;
   }
}

OAEP::OAEP(std::unique_ptr<HashFunction> hash, std::string_view P) : m_mgf1_hash(std::move(hash)) {
   m_Phash = m_mgf1_hash->process(P);
}

OAEP::OAEP(std::unique_ptr<HashFunction> hash, std::unique_ptr<HashFunction> mgf1_hash, std::string_view P) :
      m_mgf1_hash(std::move(mgf1_hash)) {
   auto phash = std::move(hash);
   m_Phash = phash->process(P);
}

}  // namespace Botan
