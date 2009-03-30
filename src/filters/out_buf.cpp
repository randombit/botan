/*
* Pipe Output Buffer Source file
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/out_buf.h>
#include <botan/secqueue.h>

namespace Botan {

/*
* Read data from a message
*/
u32bit Output_Buffers::read(byte output[], u32bit length,
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
u32bit Output_Buffers::peek(byte output[], u32bit length,
                            u32bit stream_offset,
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
u32bit Output_Buffers::remaining(Pipe::message_id msg) const
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
   if(!queue)
      throw Internal_Error("Output_Buffers::add: Argument was NULL");

   if(buffers.size() == buffers.max_size())
      throw Internal_Error("Output_Buffers::add: No more room in container");

   buffers.push_back(queue);
   }

/*
* Retire old output queues
*/
void Output_Buffers::retire()
   {
   while(buffers.size())
      {
      if(buffers[0] == 0 || buffers[0]->size() == 0)
         {
         delete buffers[0];
         buffers.pop_front();
         offset = offset + Pipe::message_id(1);
         }
      else
         break;
      }
   }

/*
* Get a particular output queue
*/
SecureQueue* Output_Buffers::get(Pipe::message_id msg) const
   {
   if(msg < offset)
      return 0;
   if(msg > message_count())
      throw Internal_Error("Output_Buffers::get: msg > size");

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
   for(u32bit j = 0; j != buffers.size(); ++j)
      delete buffers[j];
   }

}
