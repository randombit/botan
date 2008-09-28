/*************************************************
* OFB Mode Source File                           *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/ofb.h>
#include <botan/lookup.h>
#include <botan/xor_buf.h>
#include <algorithm>

namespace Botan {

/*************************************************
* OFB Constructor                                *
*************************************************/
OFB::OFB(const std::string& cipher_name) :
   BlockCipherMode(cipher_name, "OFB", block_size_of(cipher_name), 2)
   {
   }

/*************************************************
* OFB Constructor                                *
*************************************************/
OFB::OFB(const std::string& cipher_name, const SymmetricKey& key,
         const InitializationVector& iv) :
   BlockCipherMode(cipher_name, "OFB", block_size_of(cipher_name), 2)
   {
   set_key(key);
   set_iv(iv);
   }

/*************************************************
* OFB Encryption/Decryption                      *
*************************************************/
void OFB::write(const byte input[], u32bit length)
   {
   u32bit copied = std::min(BLOCK_SIZE - position, length);
   xor_buf(buffer, input, state + position, copied);
   send(buffer, copied);
   input += copied;
   length -= copied;
   position += copied;

   if(position == BLOCK_SIZE)
      {
      cipher->encrypt(state);
      position = 0;
      }

   while(length >= BLOCK_SIZE)
      {
      xor_buf(buffer, input, state, BLOCK_SIZE);
      send(buffer, BLOCK_SIZE);

      input += BLOCK_SIZE;
      length -= BLOCK_SIZE;
      cipher->encrypt(state);
      }

   xor_buf(buffer, input, state + position, length);
   send(buffer, length);
   position += length;
   }

}
