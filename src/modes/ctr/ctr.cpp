/*
* CTR Mode
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ctr.h>
#include <botan/xor_buf.h>
#include <algorithm>

namespace Botan {

namespace {

const u32bit PARALLEL_BLOCKS = BOTAN_PARALLEL_BLOCKS_CTR;

}

/*
* CTR-BE Constructor
*/
CTR_BE::CTR_BE(BlockCipher* ciph) : cipher(ciph)
   {
   position = 0;

   counter.create(ciph->BLOCK_SIZE * PARALLEL_BLOCKS);
   enc_buffer.create(ciph->BLOCK_SIZE * PARALLEL_BLOCKS);
   }

/*
* CTR-BE Constructor
*/
CTR_BE::CTR_BE(BlockCipher* ciph, const SymmetricKey& key,
               const InitializationVector& iv) :
   cipher(ciph)
   {
   position = 0;

   counter.create(ciph->BLOCK_SIZE * PARALLEL_BLOCKS);
   enc_buffer.create(ciph->BLOCK_SIZE * PARALLEL_BLOCKS);

   cipher->set_key(key);
   set_iv(iv);
   }

/*
* CTR_BE Destructor
*/
CTR_BE::~CTR_BE()
   {
   delete cipher;
   }

/*
* Return the name of this type
*/
std::string CTR_BE::name() const
   {
   return ("CTR-BE/" + cipher->name());
   }

/*
* Set CTR-BE IV
*/
void CTR_BE::set_iv(const InitializationVector& iv)
   {
   const u32bit BLOCK_SIZE = cipher->BLOCK_SIZE;

   if(iv.length() != BLOCK_SIZE)
      throw Invalid_IV_Length(name(), iv.length());

   enc_buffer.clear();
   position = 0;

   counter.copy(0, iv.begin(), iv.length());

   for(u32bit i = 1; i != PARALLEL_BLOCKS; ++i)
      {
      counter.copy(i*BLOCK_SIZE,
                   counter.begin() + (i-1)*BLOCK_SIZE, BLOCK_SIZE);

      for(s32bit j = BLOCK_SIZE - 1; j >= 0; --j)
         if(++counter[i*BLOCK_SIZE+j])
            break;
      }

   cipher->encrypt_n(counter, enc_buffer, PARALLEL_BLOCKS);
   }

/*
* CTR-BE Encryption/Decryption
*/
void CTR_BE::write(const byte input[], u32bit length)
   {
   u32bit copied = std::min(enc_buffer.size() - position, length);
   xor_buf(enc_buffer + position, input, copied);
   send(enc_buffer + position, copied);
   input += copied;
   length -= copied;
   position += copied;

   if(position == enc_buffer.size())
      increment_counter();

   while(length >= enc_buffer.size())
      {
      xor_buf(enc_buffer, input, enc_buffer.size());
      send(enc_buffer, enc_buffer.size());

      input += enc_buffer.size();
      length -= enc_buffer.size();
      increment_counter();
      }

   xor_buf(enc_buffer + position, input, length);
   send(enc_buffer + position, length);
   position += length;
   }

/*
* Increment the counter and update the buffer
*/
void CTR_BE::increment_counter()
   {
   for(u32bit i = 0; i != PARALLEL_BLOCKS; ++i)
      {
      byte* this_ctr = counter + i*cipher->BLOCK_SIZE;

      byte last_byte = this_ctr[cipher->BLOCK_SIZE-1];
      last_byte += PARALLEL_BLOCKS;

      if(this_ctr[cipher->BLOCK_SIZE-1] > last_byte)
         for(s32bit j = cipher->BLOCK_SIZE - 2; j >= 0; --j)
            if(++this_ctr[j])
               break;

      this_ctr[cipher->BLOCK_SIZE-1] = last_byte;
      }

   cipher->encrypt_n(counter, enc_buffer, PARALLEL_BLOCKS);

   position = 0;
   }

}
