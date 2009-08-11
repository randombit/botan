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
   if(iv.length() != cipher->BLOCK_SIZE)
      throw Invalid_IV_Length(name(), iv.length());

   enc_buffer.clear();
   position = 0;

   for(u32bit i = 0; i != PARALLEL_BLOCKS; ++i)
      {
      counter.copy(i*cipher->BLOCK_SIZE, iv.begin(), iv.length());

      // FIXME: this is stupid
      for(u32bit j = 0; j != i; ++j)
         for(s32bit k = cipher->BLOCK_SIZE - 1; k >= 0; --k)
            if(++counter[i*cipher->BLOCK_SIZE+k])
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
      // FIXME: Can do it in a single loop
      /*
      for(u32bit j = 1; j != cipher->BLOCK_SIZE; ++j)
         {
         byte carry = 0;
         byte z = counter[(i+1)*cipher->BLOCK_SIZE-1] + PARALLEL_BLOCKS;

      if(
      */
      for(u32bit j = 0; j != PARALLEL_BLOCKS; ++j)
         for(s32bit k = cipher->BLOCK_SIZE - 1; k >= 0; --k)
            if(++counter[i*cipher->BLOCK_SIZE+k])
               break;
      }

   cipher->encrypt_n(counter, enc_buffer, PARALLEL_BLOCKS);

   position = 0;
   }

}
