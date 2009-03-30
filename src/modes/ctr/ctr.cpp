/*
* CTR Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ctr.h>
#include <botan/xor_buf.h>
#include <algorithm>

namespace Botan {

/*
* CTR-BE Constructor
*/
CTR_BE::CTR_BE(BlockCipher* ciph) :
   BlockCipherMode(ciph, "CTR-BE", ciph->BLOCK_SIZE, 1)
   {
   }

/*
* CTR-BE Constructor
*/
CTR_BE::CTR_BE(BlockCipher* ciph, const SymmetricKey& key,
               const InitializationVector& iv) :
   BlockCipherMode(ciph, "CTR-BE", ciph->BLOCK_SIZE, 1)
   {
   set_key(key);
   set_iv(iv);
   }

/*
* CTR-BE Encryption/Decryption
*/
void CTR_BE::write(const byte input[], u32bit length)
   {
   u32bit copied = std::min(BLOCK_SIZE - position, length);
   xor_buf(buffer + position, input, copied);
   send(buffer + position, copied);
   input += copied;
   length -= copied;
   position += copied;

   if(position == BLOCK_SIZE)
      increment_counter();

   while(length >= BLOCK_SIZE)
      {
      xor_buf(buffer, input, BLOCK_SIZE);
      send(buffer, BLOCK_SIZE);

      input += BLOCK_SIZE;
      length -= BLOCK_SIZE;
      increment_counter();
      }

   xor_buf(buffer + position, input, length);
   send(buffer + position, length);
   position += length;
   }

/*
* Increment the counter and update the buffer
*/
void CTR_BE::increment_counter()
   {
   for(s32bit j = BLOCK_SIZE - 1; j >= 0; --j)
      if(++state[j])
         break;
   cipher->encrypt(state, buffer);
   position = 0;
   }

}
