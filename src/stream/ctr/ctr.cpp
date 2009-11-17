/*
* CTR-BE Mode Cipher
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ctr.h>
#include <botan/xor_buf.h>

namespace Botan {

/*
* CTR-BE Constructor
*/

CTR_BE::CTR_BE(BlockCipher* ciph) :
   StreamCipher(ciph->MINIMUM_KEYLENGTH,
                ciph->MAXIMUM_KEYLENGTH,
                ciph->KEYLENGTH_MULTIPLE),
   permutation(ciph)
   {
   position = 0;

   counter.resize(permutation->BLOCK_SIZE * BOTAN_PARALLEL_BLOCKS_CTR);
   buffer.resize(permutation->BLOCK_SIZE * BOTAN_PARALLEL_BLOCKS_CTR);
   }

/*
* CTR_BE Destructor
*/
CTR_BE::~CTR_BE()
   {
   delete permutation;
   }

/*
* Zeroize
*/
void CTR_BE::clear()
   {
   permutation->clear();
   buffer.clear();
   counter.clear();
   position = 0;
   }

/*
* Set the key
*/
void CTR_BE::key_schedule(const byte key[], u32bit key_len)
   {
   permutation->set_key(key, key_len);

   // Set a default all-zeros IV
   set_iv(0, 0);
   }

/*
* Return the name of this type
*/
std::string CTR_BE::name() const
   {
   return ("CTR-BE(" + permutation->name() + ")");
   }

/*
* CTR-BE Encryption/Decryption
*/
void CTR_BE::cipher(const byte in[], byte out[], u32bit length)
   {
   while(length >= buffer.size() - position)
      {
      xor_buf(out, in, buffer.begin() + position, buffer.size() - position);
      length -= (buffer.size() - position);
      in += (buffer.size() - position);
      out += (buffer.size() - position);
      increment_counter();
      }
   xor_buf(out, in, buffer.begin() + position, length);
   position += length;
   }

/*
* Set CTR-BE IV
*/
void CTR_BE::set_iv(const byte iv[], u32bit iv_len)
   {
   if(!valid_iv_length(iv_len))
      throw Invalid_IV_Length(name(), iv_len);

   const u32bit BLOCK_SIZE = permutation->BLOCK_SIZE;

   counter.clear();

   counter.copy(0, iv, iv_len);

   const u32bit PARALLEL_BLOCKS = counter.size() / BLOCK_SIZE;

   for(u32bit i = 1; i != PARALLEL_BLOCKS; ++i)
      {
      counter.copy(i*BLOCK_SIZE,
                   counter.begin() + (i-1)*BLOCK_SIZE, BLOCK_SIZE);

      for(s32bit j = BLOCK_SIZE - 1; j >= 0; --j)
         if(++counter[i*BLOCK_SIZE+j])
            break;
      }

   permutation->encrypt_n(counter, buffer, PARALLEL_BLOCKS);
   position = 0;
   }

/*
* Increment the counter and update the buffer
*/
void CTR_BE::increment_counter()
   {
   const u32bit PARALLEL_BLOCKS = counter.size() / permutation->BLOCK_SIZE;

   for(u32bit i = 0; i != PARALLEL_BLOCKS; ++i)
      {
      byte* this_ctr = counter + i*permutation->BLOCK_SIZE;

      byte last_byte = this_ctr[permutation->BLOCK_SIZE-1];
      last_byte += PARALLEL_BLOCKS;

      if(this_ctr[permutation->BLOCK_SIZE-1] > last_byte)
         for(s32bit j = permutation->BLOCK_SIZE - 2; j >= 0; --j)
            if(++this_ctr[j])
               break;

      this_ctr[permutation->BLOCK_SIZE-1] = last_byte;
      }

   permutation->encrypt_n(counter, buffer, PARALLEL_BLOCKS);

   position = 0;
   }

}
