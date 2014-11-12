/*
* EAX Mode Encryption
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eax.h>
#include <botan/internal/xor_buf.h>
#include <botan/parsing.h>
#include <algorithm>

namespace Botan {

/*
* EAX_Decryption Constructor
*/
EAX_Decryption::EAX_Decryption(BlockCipher* ciph,
                               size_t tag_size) :
   EAX_Base(ciph, tag_size)
   {
   queue.resize(2*TAG_SIZE + DEFAULT_BUFFERSIZE);
   queue_start = queue_end = 0;
   }

/*
* EAX_Decryption Constructor
*/
EAX_Decryption::EAX_Decryption(BlockCipher* ciph,
                               const SymmetricKey& key,
                               const InitializationVector& iv,
                               size_t tag_size) :
   EAX_Base(ciph, tag_size)
   {
   set_key(key);
   set_iv(iv);
   queue.resize(2*TAG_SIZE + DEFAULT_BUFFERSIZE);
   queue_start = queue_end = 0;
   }

/*
* Decrypt in EAX mode
*/
void EAX_Decryption::write(const byte input[], size_t length)
   {
   while(length)
      {
      const size_t copied = std::min<size_t>(length, queue.size() - queue_end);

      queue.copy(queue_end, input, copied);
      input += copied;
      length -= copied;
      queue_end += copied;

      while((queue_end - queue_start) > TAG_SIZE)
         {
         size_t removed = (queue_end - queue_start) - TAG_SIZE;
         do_write(&queue[queue_start], removed);
         queue_start += removed;
         }

      if(queue_start + TAG_SIZE == queue_end &&
         queue_start >= queue.size() / 2)
         {
         SecureVector<byte> queue_data(TAG_SIZE);
         queue_data.copy(&queue[queue_start], TAG_SIZE);
         queue.copy(&queue_data[0], TAG_SIZE);
         queue_start = 0;
         queue_end = TAG_SIZE;
         }
      }
   }

/*
* Decrypt in EAX mode
*/
void EAX_Decryption::do_write(const byte input[], size_t length)
   {
   while(length)
      {
      size_t copied = std::min<size_t>(length, ctr_buf.size());

      /*
      Process same block with cmac and ctr at the same time to
      help cache locality.
      */
      cmac->update(input, copied);
      ctr->cipher(input, &ctr_buf[0], copied);
      send(ctr_buf, copied);
      input += copied;
      length -= copied;
      }
   }

/*
* Finish decrypting in EAX mode
*/
void EAX_Decryption::end_msg()
   {
   if((queue_end - queue_start) != TAG_SIZE)
      throw Decoding_Error(name() + ": Message authentication failure");

   const byte* included_mac = &queue[queue_start];

   SecureVector<byte> computed_mac = cmac->final();

   xor_buf(&computed_mac[0], &nonce_mac[0], TAG_SIZE);
   xor_buf(&computed_mac[0], &header_mac[0], TAG_SIZE);

   if(!same_mem(included_mac, &computed_mac[0], TAG_SIZE))
      throw Decoding_Error(name() + ": Message authentication failure");

   queue_start = queue_end = 0;
   }

}
