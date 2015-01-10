/*
* Pipe Output Buffer
* (C) 1999-2007,2011 Jack Lloyd
*     2012 Markus Wanner
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/out_buf.h>
#include <botan/secqueue.h>

namespace Botan {

/*
* Read data from a message
*/
size_t Output_Buffers::read(byte output[], size_t length,
                            Pipe::message_id msg)
   {
   SecureQueue* q = get(msg);
   if(q)
      return q->read(output, length);
   return 0;
   }

/*
* Peek at data in a message
*/
size_t Output_Buffers::peek(byte output[], size_t length,
                            size_t stream_offset,
                            Pipe::message_id msg) const
   {
   SecureQueue* q = get(msg);
   if(q)
      return q->peek(output, length, stream_offset);
   return 0;
   }

/*
* Check available bytes in a message
*/
size_t Output_Buffers::remaining(Pipe::message_id msg) const
   {
   SecureQueue* q = get(msg);
   if(q)
      return q->size();
   return 0;
   }

/*
* Return the total bytes of a message that have already been read.
*/
size_t Output_Buffers::get_bytes_read(Pipe::message_id msg) const
   {
   SecureQueue* q = get(msg);
   if (q)
      return q->get_bytes_read();
   return 0;
   }

/*
* Add a new output queue
*/
void Output_Buffers::add(SecureQueue* queue)
   {
   BOTAN_ASSERT(queue, "queue was provided");

   BOTAN_ASSERT(buffers.size() < buffers.max_size(),
                "Room was available in container");

   buffers.push_back(queue);
   }

/*
* Retire old output queues
*/
void Output_Buffers::retire()
   {
   for(size_t i = 0; i != buffers.size(); ++i)
      if(buffers[i] && buffers[i]->size() == 0)
         {
         delete buffers[i];
         buffers[i] = nullptr;
         }

   while(buffers.size() && !buffers[0])
      {
      buffers.pop_front();
      offset = offset + Pipe::message_id(1);
      }
   }

/*
* Get a particular output queue
*/
SecureQueue* Output_Buffers::get(Pipe::message_id msg) const
   {
   if(msg < offset)
      return nullptr;

   BOTAN_ASSERT(msg < message_count(), "Message number is in range");

   return buffers[msg-offset];
   }

/*
* Return the total number of messages
*/
Pipe::message_id Output_Buffers::message_count() const
   {
   return (offset + buffers.size());
   }

/*
* Output_Buffers Constructor
*/
Output_Buffers::Output_Buffers()
   {
   offset = 0;
   }

/*
* Output_Buffers Destructor
*/
Output_Buffers::~Output_Buffers()
   {
   for(size_t j = 0; j != buffers.size(); ++j)
      delete buffers[j];
   }

}
