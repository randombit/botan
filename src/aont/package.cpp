/*
* Rivest's Package Tranform
*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/package.h>
#include <botan/pipe.h>
#include <botan/ctr.h>
#include <botan/loadstor.h>
#include <botan/xor_buf.h>

namespace Botan {

namespace AllOrNothingTransform {

void package(RandomNumberGenerator& rng,
             BlockCipher* cipher,
             const byte input[], u32bit input_len,
             byte output[])
   {
   if(!cipher->valid_keylength(cipher->BLOCK_SIZE))
      throw Invalid_Argument("AONT::package: Invalid cipher");

   // The all-zero string which is used both as the CTR IV and as K0
   const std::string all_zeros(cipher->BLOCK_SIZE*2, '0');

   SymmetricKey package_key(rng, cipher->BLOCK_SIZE);

   // takes ownership of cipher object
   Keyed_Filter* ctr_mode = new CTR_BE(cipher,
                                       package_key,
                                       InitializationVector(all_zeros));

   Pipe pipe(ctr_mode);

   pipe.process_msg(input, input_len);
   pipe.read(output, pipe.remaining());

   // Set K0 (the all zero key)
   cipher->set_key(SymmetricKey(all_zeros));

   SecureVector<byte> buf(cipher->BLOCK_SIZE);

   const u32bit blocks =
      (input_len + cipher->BLOCK_SIZE - 1) / cipher->BLOCK_SIZE;

   byte* final_block = output + input_len;
   clear_mem(final_block, cipher->BLOCK_SIZE);

   // XOR the hash blocks into the final block
   for(u32bit i = 0; i != blocks; ++i)
      {
      u32bit left = std::min<u32bit>(cipher->BLOCK_SIZE,
                                     input_len - cipher->BLOCK_SIZE * i);

      buf.clear();
      copy_mem(&buf[0], output + cipher->BLOCK_SIZE * i, left);

      for(u32bit j = 0; j != 4; ++j)
         buf[cipher->BLOCK_SIZE - 1 - j] ^= get_byte(3-j, i);

      cipher->encrypt(buf);

      xor_buf(final_block, buf, cipher->BLOCK_SIZE);
      }

   // XOR the random package key into the final block
   xor_buf(final_block, package_key.begin(), cipher->BLOCK_SIZE);
   }

void unpackage(BlockCipher* cipher,
               const byte input[], u32bit input_len,
               byte output[])
   {
   if(!cipher->valid_keylength(cipher->BLOCK_SIZE))
      throw Invalid_Argument("AONT::unpackage: Invalid cipher");

   if(input_len < cipher->BLOCK_SIZE)
      throw Invalid_Argument("AONT::unpackage: Input too short");

   // The all-zero string which is used both as the CTR IV and as K0
   const std::string all_zeros(cipher->BLOCK_SIZE*2, '0');

   cipher->set_key(SymmetricKey(all_zeros));

   SecureVector<byte> package_key(cipher->BLOCK_SIZE);
   SecureVector<byte> buf(cipher->BLOCK_SIZE);

   // Copy the package key (masked with the block hashes)
   copy_mem(&package_key[0],
            input + (input_len - cipher->BLOCK_SIZE),
            cipher->BLOCK_SIZE);

   const u32bit blocks = ((input_len - 1) / cipher->BLOCK_SIZE);

   // XOR the blocks into the package key bits
   for(u32bit i = 0; i != blocks; ++i)
      {
      u32bit left = std::min<u32bit>(cipher->BLOCK_SIZE,
                                     input_len - cipher->BLOCK_SIZE * (i+1));

      buf.clear();
      copy_mem(&buf[0], input + cipher->BLOCK_SIZE * i, left);

      for(u32bit j = 0; j != 4; ++j)
         buf[cipher->BLOCK_SIZE - 1 - j] ^= get_byte(3-j, i);

      cipher->encrypt(buf);

      xor_buf(&package_key[0], buf, cipher->BLOCK_SIZE);
      }

   // takes ownership of cipher object
   Pipe pipe(new CTR_BE(cipher,
                        SymmetricKey(package_key),
                        InitializationVector(all_zeros)));

   pipe.process_msg(input, input_len - cipher->BLOCK_SIZE);

   pipe.read(output, pipe.remaining());
   }

}

}
