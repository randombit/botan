/*
* Rivest's Package Tranform
*
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/package.h>
#include <botan/filters.h>
#include <botan/ctr.h>
#include <botan/loadstor.h>
#include <botan/rng.h>

namespace Botan {

void aont_package(RandomNumberGenerator& rng,
                  BlockCipher* cipher,
                  const uint8_t input[], size_t input_len,
                  uint8_t output[])
   {
   if(input_len <= 1)
      throw Encoding_Error("Package transform cannot encode small inputs");

   const size_t BLOCK_SIZE = cipher->block_size();

   if(!cipher->valid_keylength(BLOCK_SIZE))
      throw Invalid_Argument("AONT::package: Invalid cipher");

   // The all-zero string which is used both as the CTR IV and as K0
   const std::string all_zeros(BLOCK_SIZE*2, '0');

   SymmetricKey package_key(rng, BLOCK_SIZE);

   Pipe pipe(new StreamCipher_Filter(new CTR_BE(cipher), package_key));

   pipe.process_msg(input, input_len);
   const size_t remaining = pipe.remaining();
   BOTAN_ASSERT_EQUAL(remaining, pipe.read(output, remaining), "Expected read size");

   // Set K0 (the all zero key)
   cipher->set_key(SymmetricKey(all_zeros));

   secure_vector<uint8_t> buf(BLOCK_SIZE);

   const size_t blocks =
      (input_len + BLOCK_SIZE - 1) / BLOCK_SIZE;

   uint8_t* final_block = output + input_len;
   clear_mem(final_block, BLOCK_SIZE);

   // XOR the hash blocks into the final block
   for(size_t i = 0; i != blocks; ++i)
      {
      const size_t left = std::min<size_t>(BLOCK_SIZE,
                                           input_len - BLOCK_SIZE * i);

      zeroise(buf);
      copy_mem(buf.data(), output + (BLOCK_SIZE * i), left);

      for(size_t j = 0; j != sizeof(i); ++j)
         buf[BLOCK_SIZE - 1 - j] ^= get_byte(sizeof(i)-1-j, i);

      cipher->encrypt(buf.data());

      xor_buf(final_block, buf.data(), BLOCK_SIZE);
      }

   // XOR the random package key into the final block
   xor_buf(final_block, package_key.begin(), BLOCK_SIZE);
   }

void aont_unpackage(BlockCipher* cipher,
                    const uint8_t input[], size_t input_len,
                    uint8_t output[])
   {
   const size_t BLOCK_SIZE = cipher->block_size();

   if(!cipher->valid_keylength(BLOCK_SIZE))
      throw Invalid_Argument("AONT::unpackage: Invalid cipher");

   if(input_len < BLOCK_SIZE)
      throw Invalid_Argument("AONT::unpackage: Input too short");

   // The all-zero string which is used both as the CTR IV and as K0
   const std::string all_zeros(BLOCK_SIZE*2, '0');

   cipher->set_key(SymmetricKey(all_zeros));

   secure_vector<uint8_t> package_key(BLOCK_SIZE);
   secure_vector<uint8_t> buf(BLOCK_SIZE);

   // Copy the package key (masked with the block hashes)
   copy_mem(package_key.data(),
            input + (input_len - BLOCK_SIZE),
            BLOCK_SIZE);

   const size_t blocks = ((input_len - 1) / BLOCK_SIZE);

   // XOR the blocks into the package key bits
   for(size_t i = 0; i != blocks; ++i)
      {
      const size_t left = std::min<size_t>(BLOCK_SIZE,
                                           input_len - BLOCK_SIZE * (i+1));

      zeroise(buf);
      copy_mem(buf.data(), input + (BLOCK_SIZE * i), left);

      for(size_t j = 0; j != sizeof(i); ++j)
         buf[BLOCK_SIZE - 1 - j] ^= get_byte(sizeof(i)-1-j, i);

      cipher->encrypt(buf.data());

      xor_buf(package_key.data(), buf.data(), BLOCK_SIZE);
      }

   Pipe pipe(new StreamCipher_Filter(new CTR_BE(cipher), package_key));

   pipe.process_msg(input, input_len - BLOCK_SIZE);

   const size_t remaining = pipe.remaining();
   BOTAN_ASSERT_EQUAL(remaining, pipe.read(output, remaining), "Expected read size");
   }

}
