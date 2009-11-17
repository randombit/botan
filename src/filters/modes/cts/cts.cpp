/*
* CTS Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cts.h>
#include <botan/xor_buf.h>
#include <algorithm>

namespace Botan {

/*
* Encrypt a block
*/
void CTS_Encryption::encrypt(const byte block[])
   {
   xor_buf(state, block, BLOCK_SIZE);
   cipher->encrypt(state);
   send(state, BLOCK_SIZE);
   }

/*
* Encrypt in CTS mode
*/
void CTS_Encryption::write(const byte input[], u32bit length)
   {
   u32bit copied = std::min(BUFFER_SIZE - position, length);
   buffer.copy(position, input, copied);
   length -= copied;
   input += copied;
   position += copied;

   if(length == 0) return;

   encrypt(buffer);
   if(length > BLOCK_SIZE)
      {
      encrypt(buffer + BLOCK_SIZE);
      while(length > 2*BLOCK_SIZE)
         {
         encrypt(input);
         length -= BLOCK_SIZE;
         input += BLOCK_SIZE;
         }
      position = 0;
      }
   else
      {
      copy_mem(buffer.begin(), buffer + BLOCK_SIZE, BLOCK_SIZE);
      position = BLOCK_SIZE;
      }
   buffer.copy(position, input, length);
   position += length;
   }

/*
* Finish encrypting in CTS mode
*/
void CTS_Encryption::end_msg()
   {
   if(position < BLOCK_SIZE + 1)
      throw Exception("CTS_Encryption: insufficient data to encrypt");
   xor_buf(state, buffer, BLOCK_SIZE);
   cipher->encrypt(state);
   SecureVector<byte> cn = state;
   clear_mem(buffer + position, BUFFER_SIZE - position);
   encrypt(buffer + BLOCK_SIZE);
   send(cn, position - BLOCK_SIZE);
   }

/*
* Decrypt a block
*/
void CTS_Decryption::decrypt(const byte block[])
   {
   cipher->decrypt(block, temp);
   xor_buf(temp, state, BLOCK_SIZE);
   send(temp, BLOCK_SIZE);
   state.copy(block, BLOCK_SIZE);
   }

/*
* Decrypt in CTS mode
*/
void CTS_Decryption::write(const byte input[], u32bit length)
   {
   u32bit copied = std::min(BUFFER_SIZE - position, length);
   buffer.copy(position, input, copied);
   length -= copied;
   input += copied;
   position += copied;

   if(length == 0) return;

   decrypt(buffer);
   if(length > BLOCK_SIZE)
      {
      decrypt(buffer + BLOCK_SIZE);
      while(length > 2*BLOCK_SIZE)
         {
         decrypt(input);
         length -= BLOCK_SIZE;
         input += BLOCK_SIZE;
         }
      position = 0;
      }
   else
      {
      copy_mem(buffer.begin(), buffer + BLOCK_SIZE, BLOCK_SIZE);
      position = BLOCK_SIZE;
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
   xor_buf(temp, buffer + BLOCK_SIZE, position - BLOCK_SIZE);
   SecureVector<byte> xn = temp;
   copy_mem(buffer + position, xn + (position - BLOCK_SIZE),
            BUFFER_SIZE - position);
   cipher->decrypt(buffer + BLOCK_SIZE, temp);
   xor_buf(temp, state, BLOCK_SIZE);
   send(temp, BLOCK_SIZE);
   send(xn, position - BLOCK_SIZE);
   }

}
