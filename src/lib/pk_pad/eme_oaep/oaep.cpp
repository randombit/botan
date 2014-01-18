/*
* OAEP
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/oaep.h>
#include <botan/mgf1.h>
#include <botan/mem_ops.h>

namespace Botan {

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

   rng.randomize(&out[0], m_Phash.size());

   buffer_insert(out, m_Phash.size(), &m_Phash[0], m_Phash.size());
   out[out.size() - in_length - 1] = 0x01;
   buffer_insert(out, out.size() - in_length, in, in_length);

   mgf1_mask(*m_hash,
             &out[0], m_Phash.size(),
             &out[m_Phash.size()], out.size() - m_Phash.size());

   mgf1_mask(*m_hash,
             &out[m_Phash.size()], out.size() - m_Phash.size(),
             &out[0], m_Phash.size());

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
             &input[0], m_Phash.size());

   mgf1_mask(*m_hash,
             &input[0], m_Phash.size(),
             &input[m_Phash.size()], input.size() - m_Phash.size());

   bool waiting_for_delim = true;
   bool bad_input = false;
   size_t delim_idx = 2 * m_Phash.size();

   /*
   * GCC 4.5 on x86-64 compiles this in a way that is still vunerable
   * to timing analysis. Other compilers, or GCC on other platforms,
   * may or may not.
   */
   for(size_t i = delim_idx; i < input.size(); ++i)
      {
      const bool zero_p = !input[i];
      const bool one_p = input[i] == 0x01;

      const bool add_1 = waiting_for_delim && zero_p;

      bad_input |= waiting_for_delim && !(zero_p || one_p);

      delim_idx += add_1;

      waiting_for_delim &= zero_p;
      }

   // If we never saw any non-zero byte, then it's not valid input
   bad_input |= waiting_for_delim;

   bad_input |= !same_mem(&input[m_Phash.size()], &m_Phash[0], m_Phash.size());

   if(bad_input)
      throw Decoding_Error("Invalid OAEP encoding");

   return secure_vector<byte>(&input[delim_idx + 1], &input[input.size()]);
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
