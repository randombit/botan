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
   buffer.resize(2 * cipher->block_size());
   state.resize(cipher->block_size());
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
   buffer.resize(2 * cipher->block_size());
   state.resize(cipher->block_size());
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
   xor_buf(state, block, cipher->block_size());
   cipher->encrypt(state);
   send(state, cipher->block_size());
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
   if(length > cipher->block_size())
      {
      encrypt(&buffer[cipher->block_size()]);
      while(length > 2*cipher->block_size())
         {
         encrypt(input);
         length -= cipher->block_size();
         input += cipher->block_size();
         }
      position = 0;
      }
   else
      {
      copy_mem(&buffer[0], &buffer[cipher->block_size()], cipher->block_size());
      position = cipher->block_size();
      }
   buffer.copy(position, input, length);
   position += length;
   }

/*
* Finish encrypting in CTS mode
*/
void CTS_Encryption::end_msg()
   {
   if(position < cipher->block_size() + 1)
      throw Encoding_Error(name() + ": insufficient data to encrypt");

   xor_buf(state, buffer, cipher->block_size());
   cipher->encrypt(state);
   SecureVector<byte> cn = state;
   clear_mem(&buffer[position], buffer.size() - position);
   encrypt(&buffer[cipher->block_size()]);
   send(cn, position - cipher->block_size());
   }

/*
* CTS Decryption Constructor
*/
CTS_Decryption::CTS_Decryption(BlockCipher* ciph) :
   cipher(ciph)
   {
   buffer.resize(2 * cipher->block_size());
   state.resize(cipher->block_size());
   temp.resize(cipher->block_size());
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
   buffer.resize(2 * cipher->block_size());
   state.resize(cipher->block_size());
   temp.resize(cipher->block_size());
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
   xor_buf(temp, state, cipher->block_size());
   send(temp, cipher->block_size());
   state.copy(block, cipher->block_size());
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
   if(length > cipher->block_size())
      {
      decrypt(&buffer[cipher->block_size()]);
      while(length > 2*cipher->block_size())
         {
         decrypt(input);
         length -= cipher->block_size();
         input += cipher->block_size();
         }
      position = 0;
      }
   else
      {
      copy_mem(&buffer[0], &buffer[cipher->block_size()], cipher->block_size());
      position = cipher->block_size();
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
   xor_buf(temp, &buffer[cipher->block_size()], position - cipher->block_size());

   SecureVector<byte> xn = temp;

   copy_mem(&buffer[position],
            &xn[position - cipher->block_size()],
            buffer.size() - position);

   cipher->decrypt(&buffer[cipher->block_size()], temp);
   xor_buf(temp, state, cipher->block_size());
   send(temp, cipher->block_size());
   send(xn, position - cipher->block_size());
   }

}
