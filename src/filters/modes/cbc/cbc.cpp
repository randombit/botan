/*
* CBC Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cbc.h>
#include <botan/internal/xor_buf.h>
#include <algorithm>

namespace Botan {

/*
* CBC Encryption Constructor
*/
CBC_Encryption::CBC_Encryption(BlockCipher* ciph,
                               BlockCipherModePaddingMethod* pad) :
   Buffered_Filter(ciph->block_size(), 0),
   cipher(ciph), padder(pad)
   {
   if(!padder->valid_blocksize(cipher->block_size()))
      throw Invalid_Block_Size(name(), padder->name());

   state.resize(cipher->block_size());
   }

/*
* CBC Encryption Constructor
*/
CBC_Encryption::CBC_Encryption(BlockCipher* ciph,
                               BlockCipherModePaddingMethod* pad,
                               const SymmetricKey& key,
                               const InitializationVector& iv) :
   Buffered_Filter(ciph->block_size(), 0),
   cipher(ciph), padder(pad)
   {
   if(!padder->valid_blocksize(cipher->block_size()))
      throw Invalid_Block_Size(name(), padder->name());

   state.resize(cipher->block_size());

   set_key(key);
   set_iv(iv);
   }

/*
* Set the IV
*/
void CBC_Encryption::set_iv(const InitializationVector& iv)
   {
   if(!valid_iv_length(iv.length()))
      throw Invalid_IV_Length(name(), iv.length());

   state = iv.bits_of();
   buffer_reset();
   }

/*
* Encrypt in CBC mode
*/
void CBC_Encryption::buffered_block(const byte input[], size_t length)
   {
   size_t blocks = length / state.size();

   for(size_t i = 0; i != blocks; ++i)
      {
      xor_buf(state, input + i * cipher->block_size(), state.size());
      cipher->encrypt(state);
      send(state, state.size());
      }
   }

/*
* Finish encrypting in CBC mode
*/
void CBC_Encryption::buffered_final(const byte input[], size_t length)
   {
   if(length % cipher->block_size() == 0)
      buffered_block(input, length);
   else if(length != 0)
      throw Encoding_Error(name() + ": Did not pad to full blocksize");
   }

void CBC_Encryption::write(const byte input[], size_t input_length)
   {
   Buffered_Filter::write(input, input_length);
   }

void CBC_Encryption::end_msg()
   {
   size_t last_block = current_position() % cipher->block_size();

   SecureVector<byte> padding(cipher->block_size());
   padder->pad(padding, padding.size(), last_block);

   size_t pad_bytes = padder->pad_bytes(cipher->block_size(), last_block);

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
   Buffered_Filter(ciph->parallel_bytes(), ciph->block_size()),
   cipher(ciph), padder(pad)
   {
   if(!padder->valid_blocksize(cipher->block_size()))
      throw Invalid_Block_Size(name(), padder->name());

   state.resize(cipher->block_size());
   temp.resize(buffered_block_size());
   }

/*
* CBC Decryption Constructor
*/
CBC_Decryption::CBC_Decryption(BlockCipher* ciph,
                               BlockCipherModePaddingMethod* pad,
                               const SymmetricKey& key,
                               const InitializationVector& iv) :
   Buffered_Filter(ciph->parallel_bytes(), ciph->block_size()),
   cipher(ciph), padder(pad)
   {
   if(!padder->valid_blocksize(cipher->block_size()))
      throw Invalid_Block_Size(name(), padder->name());

   state.resize(cipher->block_size());
   temp.resize(buffered_block_size());

   set_key(key);
   set_iv(iv);
   }

/*
* Set the IV
*/
void CBC_Decryption::set_iv(const InitializationVector& iv)
   {
   if(!valid_iv_length(iv.length()))
      throw Invalid_IV_Length(name(), iv.length());

   state = iv.bits_of();
   buffer_reset();
   }

/*
* Decrypt in CBC mode
*/
void CBC_Decryption::buffered_block(const byte input[], size_t length)
   {
   const size_t blocks_in_temp = temp.size() / cipher->block_size();
   size_t blocks = length / cipher->block_size();

   while(blocks)
      {
      size_t to_proc = std::min<size_t>(blocks, blocks_in_temp);

      cipher->decrypt_n(input, &temp[0], to_proc);

      xor_buf(temp, state, cipher->block_size());

      for(size_t i = 1; i < to_proc; ++i)
         xor_buf(&temp[i * cipher->block_size()],
                 input + (i-1) * cipher->block_size(),
                 cipher->block_size());

      copy_mem(&state[0],
               input + (to_proc - 1) * cipher->block_size(),
               cipher->block_size());

      send(temp, to_proc * cipher->block_size());

      input += to_proc * cipher->block_size();
      blocks -= to_proc;
      }
   }

/*
* Finish encrypting in CBC mode
*/
void CBC_Decryption::buffered_final(const byte input[], size_t length)
   {
   if(length == 0 || length % cipher->block_size() != 0)
      throw Decoding_Error(name() + ": Ciphertext not multiple of block size");

   size_t extra_blocks = (length - 1) / cipher->block_size();

   buffered_block(input, extra_blocks * cipher->block_size());

   input += extra_blocks * cipher->block_size();

   cipher->decrypt(input, temp);
   xor_buf(temp, state, cipher->block_size());
   send(temp, padder->unpad(temp, cipher->block_size()));

   copy_mem(&state[0], input, state.size()); // save for IV chaining
   }

/*
* Decrypt in CBC mode
*/
void CBC_Decryption::write(const byte input[], size_t length)
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
