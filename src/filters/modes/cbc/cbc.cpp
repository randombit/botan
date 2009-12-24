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
   cipher(ciph), padder(pad)
   {
   if(!padder->valid_blocksize(cipher->BLOCK_SIZE))
      throw Invalid_Block_Size(name(), padder->name());

   buffer.resize(cipher->BLOCK_SIZE);
   state.resize(cipher->BLOCK_SIZE);
   position = 0;
   }

/*
* CBC Encryption Constructor
*/
CBC_Encryption::CBC_Encryption(BlockCipher* ciph,
                               BlockCipherModePaddingMethod* pad,
                               const SymmetricKey& key,
                               const InitializationVector& iv) :
   cipher(ciph), padder(pad)
   {
   if(!padder->valid_blocksize(cipher->BLOCK_SIZE))
      throw Invalid_Block_Size(name(), padder->name());

   buffer.resize(cipher->BLOCK_SIZE);
   state.resize(cipher->BLOCK_SIZE);
   position = 0;

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
   buffer.clear();
   position = 0;
   }

/*
* Encrypt in CBC mode
*/
void CBC_Encryption::write(const byte input[], u32bit length)
   {
   while(length)
      {
      u32bit xored = std::min(cipher->BLOCK_SIZE - position, length);
      xor_buf(state + position, input, xored);
      input += xored;
      length -= xored;
      position += xored;
      if(position == cipher->BLOCK_SIZE)
         {
         cipher->encrypt(state);
         send(state, cipher->BLOCK_SIZE);
         position = 0;
         }
      }
   }

/*
* Finish encrypting in CBC mode
*/
void CBC_Encryption::end_msg()
   {
   SecureVector<byte> padding(cipher->BLOCK_SIZE);
   padder->pad(padding, padding.size(), position);
   write(padding, padder->pad_bytes(cipher->BLOCK_SIZE, position));
   if(position != 0)
      throw Exception(name() + ": Did not pad to full blocksize");
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
   cipher(ciph), padder(pad)
   {
   if(!padder->valid_blocksize(cipher->BLOCK_SIZE))
      throw Invalid_Block_Size(name(), padder->name());

   buffer.resize(cipher->BLOCK_SIZE);
   state.resize(cipher->BLOCK_SIZE);
   temp.resize(cipher->BLOCK_SIZE);
   position = 0;
   }

/*
* CBC Decryption Constructor
*/
CBC_Decryption::CBC_Decryption(BlockCipher* ciph,
                               BlockCipherModePaddingMethod* pad,
                               const SymmetricKey& key,
                               const InitializationVector& iv) :
   cipher(ciph), padder(pad)
   {
   if(!padder->valid_blocksize(cipher->BLOCK_SIZE))
      throw Invalid_Block_Size(name(), padder->name());

   buffer.resize(cipher->BLOCK_SIZE);
   state.resize(cipher->BLOCK_SIZE);
   temp.resize(cipher->BLOCK_SIZE);
   position = 0;

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
   buffer.clear();
   position = 0;
   }

/*
* Decrypt in CBC mode
*/
void CBC_Decryption::write(const byte input[], u32bit length)
   {
   while(length)
      {
      if(position == cipher->BLOCK_SIZE)
         {
         cipher->decrypt(buffer, temp);
         xor_buf(temp, state, cipher->BLOCK_SIZE);
         send(temp, cipher->BLOCK_SIZE);
         state = buffer;
         position = 0;
         }

      u32bit added = std::min(cipher->BLOCK_SIZE - position, length);
      buffer.copy(position, input, added);
      input += added;
      length -= added;
      position += added;
      }
   }

/*
* Finish decrypting in CBC mode
*/
void CBC_Decryption::end_msg()
   {
   if(position != cipher->BLOCK_SIZE)
      throw Decoding_Error(name());
   cipher->decrypt(buffer, temp);
   xor_buf(temp, state, cipher->BLOCK_SIZE);
   send(temp, padder->unpad(temp, cipher->BLOCK_SIZE));
   state = buffer;
   position = 0;
   }

/*
* Return a CBC mode name
*/
std::string CBC_Decryption::name() const
   {
   return (cipher->name() + "/CBC/" + padder->name());
   }

}
