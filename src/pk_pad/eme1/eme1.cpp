/*
* EME1
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eme1.h>
#include <botan/mgf1.h>
#include <memory>

namespace Botan {

/*
* EME1 Pad Operation
*/
SecureVector<byte> EME1::pad(const byte in[], u32bit in_length,
                             u32bit key_length,
                             RandomNumberGenerator& rng) const
   {
   key_length /= 8;

   if(in_length > key_length - 2*HASH_LENGTH - 1)
      throw Exception("EME1: Input is too large");

   SecureVector<byte> out(key_length);

   out.clear();

   rng.randomize(out, HASH_LENGTH);

   out.copy(HASH_LENGTH, Phash, Phash.size());
   out[out.size() - in_length - 1] = 0x01;
   out.copy(out.size() - in_length, in, in_length);
   mgf->mask(out, HASH_LENGTH, out + HASH_LENGTH, out.size() - HASH_LENGTH);
   mgf->mask(out + HASH_LENGTH, out.size() - HASH_LENGTH, out, HASH_LENGTH);

   return out;
   }

/*
* EME1 Unpad Operation
*/
SecureVector<byte> EME1::unpad(const byte in[], u32bit in_length,
                               u32bit key_length) const
   {
   /*
   Must be careful about error messages here; if an attacker can
   distinguish them, it is easy to use the differences as an oracle to
   find the secret key, as described in "A Chosen Ciphertext Attack on
   RSA Optimal Asymmetric Encryption Padding (OAEP) as Standardized in
   PKCS #1 v2.0", James Manger, Crypto 2001
   */

   key_length /= 8;

   // Invalid input: truncate to zero length input, causing later
   // checks to fail
   if(in_length > key_length)
      in_length = 0;

   SecureVector<byte> tmp(key_length);
   tmp.copy(key_length - in_length, in, in_length);

   mgf->mask(tmp + HASH_LENGTH, tmp.size() - HASH_LENGTH, tmp, HASH_LENGTH);
   mgf->mask(tmp, HASH_LENGTH, tmp + HASH_LENGTH, tmp.size() - HASH_LENGTH);

   const bool phash_ok = same_mem(&tmp[HASH_LENGTH], &Phash[0], Phash.size());

   bool delim_ok = true;
   u32bit delim_idx = 0;

   // Is this vulnerable to timing attacks?
   for(u32bit i = HASH_LENGTH + Phash.size(); i != tmp.size(); ++i)
      {
      if(tmp[i] && !delim_idx)
         {
         if(tmp[i] == 0x01)
            delim_idx = i;
         else
            delim_ok = false;
         }
      }

   if(delim_idx && delim_ok && phash_ok)
      {
      return SecureVector<byte>(tmp + delim_idx + 1,
                                tmp.size() - delim_idx - 1);
      }

   throw Decoding_Error("Invalid EME1 encoding");
   }

/*
* Return the max input size for a given key size
*/
u32bit EME1::maximum_input_size(u32bit keybits) const
   {
   if(keybits / 8 > 2*HASH_LENGTH + 1)
      return ((keybits / 8) - 2*HASH_LENGTH - 1);
   else
      return 0;
   }

/*
* EME1 Constructor
*/
EME1::EME1(HashFunction* hash, const std::string& P) :
   HASH_LENGTH(hash->OUTPUT_LENGTH)
   {
   Phash = hash->process(P);
   mgf = new MGF1(hash);
   }

}
