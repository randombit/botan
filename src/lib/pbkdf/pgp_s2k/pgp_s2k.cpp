/*
* OpenPGP S2K
* (C) 1999-2007,2017 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/pgp_s2k.h>

namespace Botan {

//static
uint8_t OpenPGP_S2K::encode_count(size_t desired_iterations)
   {
   /*
   Only 256 different iterations are actually representable in OpenPGP format ...
   */
   for(size_t c = 0; c < 256; ++c)
      {
      size_t decoded_iter = OpenPGP_S2K::decode_count(c);
      if(decoded_iter >= desired_iterations)
         return c;
      }
   }

//static
size_t OpenPGP_S2K::decode_count(uint8_t iter)
   {
   // See RFC 4880 section 3.7.1.3
   return (16 + (iter & 0x0F)) << ((iter >> 4) + 6);
   }

size_t OpenPGP_S2K::pbkdf(uint8_t output_buf[], size_t output_len,
                          const std::string& passphrase,
                          const uint8_t salt[], size_t salt_len,
                          size_t iterations,
                          std::chrono::milliseconds msec) const
   {
   if(iterations == 0 && msec.count() > 0) // FIXME
      throw Not_Implemented("OpenPGP_S2K does not implemented timed KDF");

   secure_vector<uint8_t> input_buf(salt_len + passphrase.size());
   if(salt_len > 0)
      {
      copy_mem(&input_buf[0], salt, salt_len);
      }
   if(passphrase.empty() == false)
      {
      copy_mem(&input_buf[salt_len],
               reinterpret_cast<const uint8_t*>(passphrase.data()),
               passphrase.size());
      }

   /*
   The input is always fully processed even if iterations is very small
   */
   const size_t to_hash = std::max(iterations, input_buf.size());

   secure_vector<uint8_t> hash_buf(m_hash->output_length());

   size_t pass = 0;
   size_t generated = 0;

   while(generated != output_len)
      {
      const size_t output_this_pass =
         std::min(hash_buf.size(), output_len - generated);

      // Preload some number of zero bytes (empty first iteration)
      std::vector<uint8_t> zero_padding(pass);
      m_hash->update(zero_padding);

      size_t left = to_hash;
      while(left > 0)
         {
         const size_t input_to_take = std::min(left, input_buf.size());
         m_hash->update(input_buf.data(), input_to_take);
         left -= input_to_take;
         }

      m_hash->final(hash_buf.data());
      copy_mem(output_buf + generated, hash_buf.data(), output_this_pass);
      generated += output_this_pass;
      ++pass;
      }

   return iterations;
   }

}
