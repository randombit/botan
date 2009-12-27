/*
* CBC Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cbc.h>
#include <botan/internal/xor_buf.h>
#include <algorithm>

#include <stdio.h>

namespace Botan {

/*
* CBC Encryption Constructor
*/
CBC_Encryption::CBC_Encryption(BlockCipher* ciph,
                               BlockCipherModePaddingMethod* pad) :
   Buffered_Filter(ciph->BLOCK_SIZE, 0),
   cipher(ciph), padder(pad)
   {
   if(!padder->valid_blocksize(cipher->BLOCK_SIZE))
      throw Invalid_Block_Size(name(), padder->name());

   state.resize(cipher->BLOCK_SIZE);
   }

/*
* CBC Encryption Constructor
*/
CBC_Encryption::CBC_Encryption(BlockCipher* ciph,
                               BlockCipherModePaddingMethod* pad,
                               const SymmetricKey& key,
                               const InitializationVector& iv) :
   Buffered_Filter(ciph->BLOCK_SIZE, 0),
   cipher(ciph), padder(pad)
   {
   if(!padder->valid_blocksize(cipher->BLOCK_SIZE))
      throw Invalid_Block_Size(name(), padder->name());

   state.resize(cipher->BLOCK_SIZE);

   set_key(key);
   set_iv(iv);
   }

/*
* Set the IV
*/
void CBC_Encryption::set_iv(const InitializationVector& iv)
   {
   if(iv.length() != state.size())
      throw Invalid_IV_Length(name(), iv.length());

   state = iv.bits_of();
   buffer_reset();
   }

/*
* Encrypt in CBC mode
*/
void CBC_Encryption::buffered_block(const byte input[], u32bit length)
   {
   u32bit blocks = length / state.size();

   for(u32bit i = 0; i != blocks; ++i)
      {
      xor_buf(state, input + i * cipher->BLOCK_SIZE, state.size());
      cipher->encrypt(state);
      send(state, state.size());
      }
   }

/*
* Finish encrypting in CBC mode
*/
void CBC_Encryption::buffered_final(const byte input[], u32bit length)
   {
   if(length % cipher->BLOCK_SIZE == 0)
      buffered_block(input, length);
   else if(length != 0)
      throw Exception(name() + ": Did not pad to full blocksize");
   }

void CBC_Encryption::write(const byte input[], u32bit input_length)
   {
   Buffered_Filter::write(input, input_length);
   }

void CBC_Encryption::end_msg()
   {
   u32bit last_block = current_position() % cipher->BLOCK_SIZE;

   SecureVector<byte> padding(cipher->BLOCK_SIZE);
   padder->pad(padding, padding.size(), last_block);

   u32bit pad_bytes = padder->pad_bytes(cipher->BLOCK_SIZE, last_block);

   if(pad_bytes)
      Buffered_Filter::write(padding, pad_bytes);
   Buffered_Filter::end_msg();
   }

/*
* Return a CBC mode name
*/
std::string CBC_Encryption::name() const
   {
   return (cipher->name() + "/CBC/" + padder->name());
   }

/*
* CBC Decryption Constructor
*/
CBC_Decryption::CBC_Decryption(BlockCipher* ciph,
                               BlockCipherModePaddingMethod* pad) :
   Buffered_Filter(BOTAN_PARALLEL_BLOCKS_CBC * ciph->BLOCK_SIZE,
                   ciph->BLOCK_SIZE),
   cipher(ciph), padder(pad)
   {
   if(!padder->valid_blocksize(cipher->BLOCK_SIZE))
      throw Invalid_Block_Size(name(), padder->name());

   state.resize(cipher->BLOCK_SIZE);
   temp.resize(BOTAN_PARALLEL_BLOCKS_CBC * cipher->BLOCK_SIZE);
   }

/*
* CBC Decryption Constructor
*/
CBC_Decryption::CBC_Decryption(BlockCipher* ciph,
                               BlockCipherModePaddingMethod* pad,
                               const SymmetricKey& key,
                               const InitializationVector& iv) :
   Buffered_Filter(BOTAN_PARALLEL_BLOCKS_CBC * ciph->BLOCK_SIZE,
                   ciph->BLOCK_SIZE),
   cipher(ciph), padder(pad)
   {
   if(!padder->valid_blocksize(cipher->BLOCK_SIZE))
      throw Invalid_Block_Size(name(), padder->name());

   state.resize(cipher->BLOCK_SIZE);
   temp.resize(BOTAN_PARALLEL_BLOCKS_CBC * cipher->BLOCK_SIZE);

   set_key(key);
   set_iv(iv);
   }

/*
* Set the IV
*/
void CBC_Decryption::set_iv(const InitializationVector& iv)
   {
   if(iv.length() != state.size())
      throw Invalid_IV_Length(name(), iv.length());

   state = iv.bits_of();
   buffer_reset();
   }

/*
* Decrypt in CBC mode
*/
void CBC_Decryption::buffered_block(const byte input[], u32bit length)
   {
   const u32bit blocks_in_temp = temp.size() / cipher->BLOCK_SIZE;
   u32bit blocks = length / cipher->BLOCK_SIZE;

   while(blocks)
      {
      u32bit to_proc = std::min<u32bit>(blocks, blocks_in_temp);

      cipher->decrypt_n(input, &temp[0], to_proc);

      xor_buf(temp, state, cipher->BLOCK_SIZE);

      for(u32bit i = 1; i < to_proc; ++i)
         xor_buf(temp + i * cipher->BLOCK_SIZE,
                 input + (i-1) * cipher->BLOCK_SIZE,
                 cipher->BLOCK_SIZE);

      state.set(input + (to_proc - 1) * cipher->BLOCK_SIZE, cipher->BLOCK_SIZE);

      send(temp, to_proc * cipher->BLOCK_SIZE);

      input += to_proc * cipher->BLOCK_SIZE;
      blocks -= to_proc;
      }
   }

/*
* Finish encrypting in CBC mode
*/
void CBC_Decryption::buffered_final(const byte input[], u32bit length)
   {
   if(length == 0 || length % cipher->BLOCK_SIZE != 0)
      throw Decoding_Error(name() + ": Ciphertext not multiple of block size");

   size_t extra_blocks = (length - 1) / cipher->BLOCK_SIZE;

   buffered_block(input, extra_blocks * cipher->BLOCK_SIZE);

   input += extra_blocks * cipher->BLOCK_SIZE;

   cipher->decrypt(input, temp);
   xor_buf(temp, state, cipher->BLOCK_SIZE);
   send(temp, padder->unpad(temp, cipher->BLOCK_SIZE));

   state.set(input, state.size());
   }

/*
* Decrypt in CBC mode
*/
void CBC_Decryption::write(const byte input[], u32bit length)
   {
   Buffered_Filter::write(input, length);
   }

/*
* Finish decrypting in CBC mode
*/
void CBC_Decryption::end_msg()
   {
   Buffered_Filter::end_msg();
   }

/*
* Return a CBC mode name
*/
std::string CBC_Decryption::name() const
   {
   return (cipher->name() + "/CBC/" + padder->name());
   }

}
