/*
* EAX Mode Encryption
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eax.h>
#include <botan/xor_buf.h>
#include <botan/parsing.h>
#include <algorithm>

namespace Botan {

/*
* EAX_Decryption Constructor
*/
EAX_Decryption::EAX_Decryption(BlockCipher* ciph,
                               u32bit tag_size) :
   EAX_Base(ciph, tag_size)
   {
   queue.create(2*TAG_SIZE + DEFAULT_BUFFERSIZE);
   queue_start = queue_end = 0;
   }

/*
* EAX_Decryption Constructor
*/
EAX_Decryption::EAX_Decryption(BlockCipher* ciph,
                               const SymmetricKey& key,
                               const InitializationVector& iv,
                               u32bit tag_size) :
   EAX_Base(ciph, tag_size)
   {
   set_key(key);
   set_iv(iv);
   queue.create(2*TAG_SIZE + DEFAULT_BUFFERSIZE);
   queue_start = queue_end = 0;
   }

/*
* Decrypt in EAX mode
*/
void EAX_Decryption::write(const byte input[], u32bit length)
   {
   while(length)
      {
      const u32bit copied = std::min(length, queue.size() - queue_end);

      queue.copy(queue_end, input, copied);
      input += copied;
      length -= copied;
      queue_end += copied;

      SecureVector<byte> block_buf(cipher->BLOCK_SIZE);
      while((queue_end - queue_start) > TAG_SIZE)
         {
         u32bit removed = (queue_end - queue_start) - TAG_SIZE;
         do_write(queue + queue_start, removed);
         queue_start += removed;
         }

      if(queue_start + TAG_SIZE == queue_end &&
         queue_start >= queue.size() / 2)
         {
         SecureVector<byte> queue_data(TAG_SIZE);
         queue_data.copy(queue + queue_start, TAG_SIZE);
         queue.copy(queue_data, TAG_SIZE);
         queue_start = 0;
         queue_end = TAG_SIZE;
         }
      }
   }

/*
* Decrypt in EAX mode
*/
void EAX_Decryption::do_write(const byte input[], u32bit length)
   {
   mac->update(input, length);

   u32bit copied = std::min(BLOCK_SIZE - position, length);
   xor_buf(buffer + position, input, copied);
   send(buffer + position, copied);
   input += copied;
   length -= copied;
   position += copied;

   if(position == BLOCK_SIZE)
      increment_counter();

   while(length >= BLOCK_SIZE)
      {
      xor_buf(buffer, input, BLOCK_SIZE);
      send(buffer, BLOCK_SIZE);

      input += BLOCK_SIZE;
      length -= BLOCK_SIZE;
      increment_counter();
      }

   xor_buf(buffer + position, input, length);
   send(buffer + position, length);
   position += length;
   }

/*
* Finish decrypting in EAX mode
*/
void EAX_Decryption::end_msg()
   {
   if((queue_end - queue_start) != TAG_SIZE)
      throw Integrity_Failure(name() + ": Message authentication failure");

   SecureVector<byte> data_mac = mac->final();

   for(u32bit j = 0; j != TAG_SIZE; ++j)
      if(queue[queue_start+j] != (data_mac[j] ^ nonce_mac[j] ^ header_mac[j]))
         throw Integrity_Failure(name() + ": Message authentication failure");

   state.clear();
   buffer.clear();
   position = 0;
   queue_start = queue_end = 0;
   }

}
