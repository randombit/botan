/*
* Counter mode
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ctr.h>
#include <botan/internal/xor_buf.h>

namespace Botan {

/*
* CTR-BE Constructor
*/

CTR_BE::CTR_BE(BlockCipher* ciph) :
   permutation(ciph),
   counter(256 * permutation->block_size()),
   buffer(counter.size()),
   position(0)
   {
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

   for(size_t i = 1; i != 256; ++i)
      {
      counter.copy(i*BLOCK_SIZE,
                   &counter[(i-1)*BLOCK_SIZE],
                   BLOCK_SIZE);

      for(size_t j = 0; j != BLOCK_SIZE; ++j)
         if(++counter[i*BLOCK_SIZE + (BLOCK_SIZE-1-j)])
            break;
      }

   permutation->encrypt_n(&counter[0], &buffer[0], 256);
   position = 0;
   }

/*
* Increment the counter and update the buffer
*/
void CTR_BE::increment_counter()
   {
   const size_t BLOCK_SIZE = permutation->block_size();

   for(size_t i = 0; i != 256; ++i)
      {
      for(size_t j = 1; j != BLOCK_SIZE; ++j)
         if(++counter[i*BLOCK_SIZE + (BLOCK_SIZE-1-j)])
            break;
      }

   permutation->encrypt_n(&counter[0], &buffer[0], 256);

   position = 0;
   }

}
