/*
* OAEP
* (C) 1999-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/oaep.h>
#include <botan/mgf1.h>
#include <botan/exceptn.h>
#include <botan/rng.h>
#include <botan/internal/ct_utils.h>

namespace Botan {

/*
* OAEP Pad Operation
*/
secure_vector<uint8_t> OAEP::pad(const uint8_t in[], size_t in_length,
                             size_t key_length,
                             RandomNumberGenerator& rng) const
   {
   key_length /= 8;

   if(in_length > maximum_input_size(key_length * 8))
      {
      throw Invalid_Argument("OAEP: Input is too large");
      }

   secure_vector<uint8_t> out(key_length);

   rng.randomize(out.data(), m_Phash.size());

   buffer_insert(out, m_Phash.size(), m_Phash.data(), m_Phash.size());
   out[out.size() - in_length - 1] = 0x01;
   buffer_insert(out, out.size() - in_length, in, in_length);

   mgf1_mask(*m_hash,
             out.data(), m_Phash.size(),
             &out[m_Phash.size()], out.size() - m_Phash.size());

   mgf1_mask(*m_hash,
             &out[m_Phash.size()], out.size() - m_Phash.size(),
             out.data(), m_Phash.size());

   return out;
   }

/*
* OAEP Unpad Operation
*/
secure_vector<uint8_t> OAEP::unpad(uint8_t& valid_mask,
                                const uint8_t in[], size_t in_length) const
   {
   /*
   Must be careful about error messages here; if an attacker can
   distinguish them, it is easy to use the differences as an oracle to
   find the secret key, as described in "A Chosen Ciphertext Attack on
   RSA Optimal Asymmetric Encryption Padding (OAEP) as Standardized in
   PKCS #1 v2.0", James Manger, Crypto 2001

   Also have to be careful about timing attacks! Pointed out by Falko
   Strenzke.
    
   According to the standard (Section 7.1.1), the encryptor always 
   creates a message as follows:
      i. Concatenate a single octet with hexadecimal value 0x00,
         maskedSeed, and maskedDB to form an encoded message EM of
         length k octets as
            EM = 0x00 || maskedSeed || maskedDB.
   where k is the length of the modulus N.
   Therefore, the first byte can always be skipped safely.
   */

   uint8_t skip_first = CT::is_zero<uint8_t>(in[0]) & 0x01;
   
   secure_vector<uint8_t> input(in + skip_first, in + in_length);

   CT::poison(input.data(), input.size());

   const size_t hlen = m_Phash.size();

   mgf1_mask(*m_hash,
             &input[hlen], input.size() - hlen,
             input.data(), hlen);

   mgf1_mask(*m_hash,
             input.data(), hlen,
             &input[hlen], input.size() - hlen);

   size_t delim_idx = 2 * hlen;
   uint8_t waiting_for_delim = 0xFF;
   uint8_t bad_input = 0;

   for(size_t i = delim_idx; i < input.size(); ++i)
      {
      const uint8_t zero_m = CT::is_zero<uint8_t>(input[i]);
      const uint8_t one_m = CT::is_equal<uint8_t>(input[i], 1);

      const uint8_t add_m = waiting_for_delim & zero_m;

      bad_input |= waiting_for_delim & ~(zero_m | one_m);

      delim_idx += CT::select<uint8_t>(add_m, 1, 0);

      waiting_for_delim &= zero_m;
      }

   // If we never saw any non-zero byte, then it's not valid input
   bad_input |= waiting_for_delim;
   bad_input |= CT::is_equal<uint8_t>(constant_time_compare(&input[hlen], m_Phash.data(), hlen), false);

   CT::unpoison(input.data(), input.size());
   CT::unpoison(&bad_input, 1);
   CT::unpoison(&delim_idx, 1);

   valid_mask = ~bad_input;

   secure_vector<uint8_t> output(input.begin() + delim_idx + 1, input.end());
   CT::cond_zero_mem(bad_input, output.data(), output.size());

   return output;
   }

/*
* Return the max input size for a given key size
*/
size_t OAEP::maximum_input_size(size_t keybits) const
   {
   if(keybits / 8 > 2*m_Phash.size() + 1)
      return ((keybits / 8) - 2*m_Phash.size() - 1);
   else
      return 0;
   }

/*
* OAEP Constructor
*/
OAEP::OAEP(HashFunction* hash, const std::string& P) : m_hash(hash)
   {
   m_Phash = m_hash->process(P);
   }

}
