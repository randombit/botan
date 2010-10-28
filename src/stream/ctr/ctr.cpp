/*
* CTR-BE Mode Cipher
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ctr.h>
#include <botan/internal/xor_buf.h>

namespace Botan {

/*
* CTR-BE Constructor
*/

CTR_BE::CTR_BE(BlockCipher* ciph) : permutation(ciph)
   {
   position = 0;

   counter.resize(permutation->parallel_bytes());
   buffer.resize(counter.size());
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
   zeroise(buffer);
   zeroise(counter);
   position = 0;
   }

/*
* Set the key
*/
void CTR_BE::key_schedule(const byte key[], size_t key_len)
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
void CTR_BE::cipher(const byte in[], byte out[], size_t length)
   {
   while(length >= buffer.size() - position)
      {
      xor_buf(out, in, &buffer[position], buffer.size() - position);
      length -= (buffer.size() - position);
      in += (buffer.size() - position);
      out += (buffer.size() - position);
      increment_counter();
      }
   xor_buf(out, in, &buffer[position], length);
   position += length;
   }

/*
* Set CTR-BE IV
*/
void CTR_BE::set_iv(const byte iv[], size_t iv_len)
   {
   if(!valid_iv_length(iv_len))
      throw Invalid_IV_Length(name(), iv_len);

   const size_t BLOCK_SIZE = permutation->block_size();

   zeroise(counter);

   counter.copy(0, iv, iv_len);

   const size_t PARALLEL_BLOCKS = counter.size() / BLOCK_SIZE;

   for(size_t i = 1; i != PARALLEL_BLOCKS; ++i)
      {
      counter.copy(i*BLOCK_SIZE,
                   &counter[(i-1)*BLOCK_SIZE],
                   BLOCK_SIZE);

      for(s32bit j = BLOCK_SIZE - 1; j >= 0; --j)
         if(++counter[i*BLOCK_SIZE+j])
            break;
      }

   permutation->encrypt_n(&counter[0], &buffer[0], PARALLEL_BLOCKS);
   position = 0;
   }

/*
* Increment the counter and update the buffer
*/
void CTR_BE::increment_counter()
   {
   const size_t BLOCK_SIZE = permutation->block_size();
   const size_t PARALLEL_BLOCKS = counter.size() / BLOCK_SIZE;

   for(size_t i = 0; i != PARALLEL_BLOCKS; ++i)
      {
      byte* this_ctr = &counter[i * BLOCK_SIZE];

      byte last_byte = this_ctr[BLOCK_SIZE-1];
      last_byte += PARALLEL_BLOCKS;

      if(this_ctr[BLOCK_SIZE-1] > last_byte)
         for(s32bit j = BLOCK_SIZE - 2; j >= 0; --j)
            if(++this_ctr[j])
               break;

      this_ctr[BLOCK_SIZE-1] = last_byte;
      }

   permutation->encrypt_n(&counter[0], &buffer[0], PARALLEL_BLOCKS);

   position = 0;
   }

}
