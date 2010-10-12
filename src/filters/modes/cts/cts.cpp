/*
* CTS Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cts.h>
#include <botan/internal/xor_buf.h>
#include <algorithm>

namespace Botan {

/*
* CTS Encryption Constructor
*/
CTS_Encryption::CTS_Encryption(BlockCipher* ciph) :
   cipher(ciph)
   {
   buffer.resize(2 * cipher->BLOCK_SIZE);
   state.resize(cipher->BLOCK_SIZE);
   position = 0;
   }

/*
* CTS Encryption Constructor
*/
CTS_Encryption::CTS_Encryption(BlockCipher* ciph,
                               const SymmetricKey& key,
                               const InitializationVector& iv) :
   cipher(ciph)
   {
   buffer.resize(2 * cipher->BLOCK_SIZE);
   state.resize(cipher->BLOCK_SIZE);
   position = 0;

   set_key(key);
   set_iv(iv);
   }

/*
* Set the IV
*/
void CTS_Encryption::set_iv(const InitializationVector& iv)
   {
   if(!valid_iv_length(iv.length()))
      throw Invalid_IV_Length(name(), iv.length());

   state = iv.bits_of();
   zeroise(buffer);
   position = 0;
   }

/*
* Encrypt a block
*/
void CTS_Encryption::encrypt(const byte block[])
   {
   xor_buf(state, block, cipher->BLOCK_SIZE);
   cipher->encrypt(state);
   send(state, cipher->BLOCK_SIZE);
   }

/*
* Encrypt in CTS mode
*/
void CTS_Encryption::write(const byte input[], size_t length)
   {
   size_t copied = std::min<size_t>(buffer.size() - position, length);
   buffer.copy(position, input, copied);
   length -= copied;
   input += copied;
   position += copied;

   if(length == 0) return;

   encrypt(&buffer[0]);
   if(length > cipher->BLOCK_SIZE)
      {
      encrypt(&buffer[cipher->BLOCK_SIZE]);
      while(length > 2*cipher->BLOCK_SIZE)
         {
         encrypt(input);
         length -= cipher->BLOCK_SIZE;
         input += cipher->BLOCK_SIZE;
         }
      position = 0;
      }
   else
      {
      copy_mem(&buffer[0], &buffer[cipher->BLOCK_SIZE], cipher->BLOCK_SIZE);
      position = cipher->BLOCK_SIZE;
      }
   buffer.copy(position, input, length);
   position += length;
   }

/*
* Finish encrypting in CTS mode
*/
void CTS_Encryption::end_msg()
   {
   if(position < cipher->BLOCK_SIZE + 1)
      throw Encoding_Error(name() + ": insufficient data to encrypt");

   xor_buf(state, buffer, cipher->BLOCK_SIZE);
   cipher->encrypt(state);
   SecureVector<byte> cn = state;
   clear_mem(&buffer[position], buffer.size() - position);
   encrypt(&buffer[cipher->BLOCK_SIZE]);
   send(cn, position - cipher->BLOCK_SIZE);
   }

/*
* CTS Decryption Constructor
*/
CTS_Decryption::CTS_Decryption(BlockCipher* ciph) :
   cipher(ciph)
   {
   buffer.resize(2 * cipher->BLOCK_SIZE);
   state.resize(cipher->BLOCK_SIZE);
   temp.resize(cipher->BLOCK_SIZE);
   position = 0;
   }

/*
* CTS Decryption Constructor
*/
CTS_Decryption::CTS_Decryption(BlockCipher* ciph,
                               const SymmetricKey& key,
                               const InitializationVector& iv) :
   cipher(ciph)
   {
   buffer.resize(2 * cipher->BLOCK_SIZE);
   state.resize(cipher->BLOCK_SIZE);
   temp.resize(cipher->BLOCK_SIZE);
   position = 0;

   set_key(key);
   set_iv(iv);
   }

/*
* Set the IV
*/
void CTS_Decryption::set_iv(const InitializationVector& iv)
   {
   if(!valid_iv_length(iv.length()))
      throw Invalid_IV_Length(name(), iv.length());

   state = iv.bits_of();
   zeroise(buffer);
   position = 0;
   }

/*
* Decrypt a block
*/
void CTS_Decryption::decrypt(const byte block[])
   {
   cipher->decrypt(block, &temp[0]);
   xor_buf(temp, state, cipher->BLOCK_SIZE);
   send(temp, cipher->BLOCK_SIZE);
   state.copy(block, cipher->BLOCK_SIZE);
   }

/*
* Decrypt in CTS mode
*/
void CTS_Decryption::write(const byte input[], size_t length)
   {
   size_t copied = std::min<size_t>(buffer.size() - position, length);
   buffer.copy(position, input, copied);
   length -= copied;
   input += copied;
   position += copied;

   if(length == 0) return;

   decrypt(buffer);
   if(length > cipher->BLOCK_SIZE)
      {
      decrypt(&buffer[cipher->BLOCK_SIZE]);
      while(length > 2*cipher->BLOCK_SIZE)
         {
         decrypt(input);
         length -= cipher->BLOCK_SIZE;
         input += cipher->BLOCK_SIZE;
         }
      position = 0;
      }
   else
      {
      copy_mem(&buffer[0], &buffer[cipher->BLOCK_SIZE], cipher->BLOCK_SIZE);
      position = cipher->BLOCK_SIZE;
      }
   buffer.copy(position, input, length);
   position += length;
   }

/*
* Finish decrypting in CTS mode
*/
void CTS_Decryption::end_msg()
   {
   cipher->decrypt(buffer, temp);
   xor_buf(temp, &buffer[cipher->BLOCK_SIZE], position - cipher->BLOCK_SIZE);

   SecureVector<byte> xn = temp;

   copy_mem(&buffer[position],
            &xn[position - cipher->BLOCK_SIZE],
            buffer.size() - position);

   cipher->decrypt(&buffer[cipher->BLOCK_SIZE], temp);
   xor_buf(temp, state, cipher->BLOCK_SIZE);
   send(temp, cipher->BLOCK_SIZE);
   send(xn, position - cipher->BLOCK_SIZE);
   }

}
