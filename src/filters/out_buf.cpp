/*
* Pipe Output Buffer
* (C) 1999-2007,2011 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/out_buf.h>
#include <botan/secqueue.h>
#include <botan/internal/assert.h>

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
* Add a new output queue
*/
void Output_Buffers::add(SecureQueue* queue)
   {
   BOTAN_ASSERT(queue, "argument was NULL");

   BOTAN_ASSERT(buffers.size() < buffers.max_size(),
                "No more room in container");

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
         buffers[i] = 0;
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
      return 0;

   BOTAN_ASSERT(msg < message_count(),
                "Message number out of range");

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
