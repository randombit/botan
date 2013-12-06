/*
* EME1 (aka OAEP)
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eme1.h>
#include <botan/mgf1.h>
#include <botan/mem_ops.h>
#include <memory>

namespace Botan {

/*
* EME1 Pad Operation
*/
SecureVector<byte> EME1::pad(const byte in[], size_t in_length,
                             size_t key_length,
                             RandomNumberGenerator& rng) const
   {
   key_length /= 8;

   if(key_length < in_length + 2*Phash.size() + 1)
      throw Invalid_Argument("EME1: Input is too large");

   SecureVector<byte> out(key_length);

   rng.randomize(&out[0], Phash.size());

   out.copy(Phash.size(), &Phash[0], Phash.size());
   out[out.size() - in_length - 1] = 0x01;
   out.copy(out.size() - in_length, in, in_length);

   mgf->mask(&out[0], Phash.size(),
             &out[Phash.size()], out.size() - Phash.size());

   mgf->mask(&out[Phash.size()], out.size() - Phash.size(),
             &out[0], Phash.size());

   return out;
   }

/*
* EME1 Unpad Operation
*/
SecureVector<byte> EME1::unpad(const byte in[], size_t in_length,
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

   SecureVector<byte> input(key_length);
   input.copy(key_length - in_length, in, in_length);

   mgf->mask(&input[Phash.size()], input.size() - Phash.size(),
             &input[0], Phash.size());
   mgf->mask(&input[0], Phash.size(),
             &input[Phash.size()], input.size() - Phash.size());

   bool waiting_for_delim = true;
   bool bad_input = false;
   size_t delim_idx = 2 * Phash.size();

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

   bad_input |= !same_mem(&input[Phash.size()], &Phash[0], Phash.size());

   if(bad_input)
      throw Decoding_Error("Invalid EME1 encoding");

   return SecureVector<byte>(input + delim_idx + 1,
                             input.size() - delim_idx - 1);
   }

/*
* Return the max input size for a given key size
*/
size_t EME1::maximum_input_size(size_t keybits) const
   {
   if(keybits / 8 > 2*Phash.size() + 1)
      return ((keybits / 8) - 2*Phash.size() - 1);
   else
      return 0;
   }

/*
* EME1 Constructor
*/
EME1::EME1(HashFunction* hash, const std::string& P)
   {
   Phash = hash->process(P);
   mgf = new MGF1(hash);
   }

}
