/*
* OAEP
* (C) 1999-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/oaep.h>
#include <botan/mgf1.h>
#include <botan/internal/ct_utils.h>

namespace Botan {

OAEP* OAEP::make(const Spec& request)
   {
   if(request.algo_name() == "OAEP" && request.arg_count_between(1, 2))
      {
      if(request.arg_count() == 1 ||
         (request.arg_count() == 2 && request.arg(1) == "MGF1"))
         {
         if(auto hash = HashFunction::create(request.arg(0)))
            return new OAEP(hash.release());
         }
      }

   return nullptr;
   }

/*
* OAEP Pad Operation
*/
secure_vector<byte> OAEP::pad(const byte in[], size_t in_length,
                             size_t key_length,
                             RandomNumberGenerator& rng) const
   {
   key_length /= 8;

   if(key_length < in_length + 2*m_Phash.size() + 1)
      throw Invalid_Argument("OAEP: Input is too large");

   secure_vector<byte> out(key_length);

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
secure_vector<byte> OAEP::unpad(const byte in[], size_t in_length,
                               size_t key_length) const
   {
   /*
   Must be careful about error messages here; if an attacker can
   distinguish them, it is easy to use the differences as an oracle to
   find the secret key, as described in "A Chosen Ciphertext Attack on
   RSA Optimal Asymmetric Encryption Padding (OAEP) as Standardized in
   PKCS #1 v2.0", James Manger, Crypto 2001

   Also have to be careful about timing attacks! Pointed out by Falko
   Strenzke.
   */

   key_length /= 8;

   // Invalid input: truncate to zero length input, causing later
   // checks to fail
   if(in_length > key_length)
      in_length = 0;

   secure_vector<byte> input(key_length);
   buffer_insert(input, key_length - in_length, in, in_length);

   mgf1_mask(*m_hash,
             &input[m_Phash.size()], input.size() - m_Phash.size(),
             input.data(), m_Phash.size());

   mgf1_mask(*m_hash,
             input.data(), m_Phash.size(),
             &input[m_Phash.size()], input.size() - m_Phash.size());

   BOTAN_CONST_TIME_POISON(input.data(), input.size());

   size_t delim_idx = 2 * m_Phash.size();
   byte waiting_for_delim = 0xFF;
   byte bad_input = 0;

   for(size_t i = delim_idx; i < input.size(); ++i)
      {
      const byte zero_m = ct_is_zero_8(input[i]);
      const byte one_m = ct_is_equal_8(input[i], 1);

      const byte add_m = waiting_for_delim & zero_m;

      bad_input |= waiting_for_delim & ~(zero_m | one_m);

      delim_idx += ct_select_mask_8(add_m, 1, 0);

      waiting_for_delim &= zero_m;
      }

   // If we never saw any non-zero byte, then it's not valid input
   bad_input |= waiting_for_delim;
   bad_input |= ct_expand_mask_8(!same_mem(&input[m_Phash.size()], m_Phash.data(), m_Phash.size()));

   BOTAN_CONST_TIME_UNPOISON(input.data(), input.size());
   BOTAN_CONST_TIME_UNPOISON(&bad_input, sizeof(bad_input));
   BOTAN_CONST_TIME_UNPOISON(&delim_idx, sizeof(delim_idx));

   if(bad_input)
      throw Decoding_Error("Invalid OAEP encoding");

   return secure_vector<byte>(input.begin() + delim_idx + 1, input.end());
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
