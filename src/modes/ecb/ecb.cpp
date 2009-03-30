/*
* ECB Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ecb.h>

namespace Botan {

/*
* Verify the IV is not set
*/
bool ECB::valid_iv_size(u32bit iv_size) const
   {
   if(iv_size == 0)
      return true;
   return false;
   }

/*
* Return an ECB mode name
*/
std::string ECB::name() const
   {
   return (cipher->name() + "/" + mode_name + "/" + padder->name());
   }

/*
* Encrypt in ECB mode
*/
void ECB_Encryption::write(const byte input[], u32bit length)
   {
   buffer.copy(position, input, length);
   if(position + length >= BLOCK_SIZE)
      {
      cipher->encrypt(buffer);
      send(buffer, BLOCK_SIZE);
      input += (BLOCK_SIZE - position);
      length -= (BLOCK_SIZE - position);
      while(length >= BLOCK_SIZE)
         {
         cipher->encrypt(input, buffer);
         send(buffer, BLOCK_SIZE);
         input += BLOCK_SIZE;
         length -= BLOCK_SIZE;
         }
      buffer.copy(input, length);
      position = 0;
      }
   position += length;
   }

/*
* Finish encrypting in ECB mode
*/
void ECB_Encryption::end_msg()
   {
   SecureVector<byte> padding(BLOCK_SIZE);
   padder->pad(padding, padding.size(), position);
   write(padding, padder->pad_bytes(BLOCK_SIZE, position));
   if(position != 0)
      throw Encoding_Error(name() + ": Did not pad to full blocksize");
   }

/*
* Decrypt in ECB mode
*/
void ECB_Decryption::write(const byte input[], u32bit length)
   {
   buffer.copy(position, input, length);
   if(position + length > BLOCK_SIZE)
      {
      cipher->decrypt(buffer);
      send(buffer, BLOCK_SIZE);
      input += (BLOCK_SIZE - position);
      length -= (BLOCK_SIZE - position);
      while(length > BLOCK_SIZE)
         {
         cipher->decrypt(input, buffer);
         send(buffer, BLOCK_SIZE);
         input += BLOCK_SIZE;
         length -= BLOCK_SIZE;
         }
      buffer.copy(input, length);
      position = 0;
      }
   position += length;
   }

/*
* Finish decrypting in ECB mode
*/
void ECB_Decryption::end_msg()
   {
   if(position != BLOCK_SIZE)
      throw Decoding_Error(name());
   cipher->decrypt(buffer);
   send(buffer, padder->unpad(buffer, BLOCK_SIZE));
   state = buffer;
   position = 0;
   }

}
