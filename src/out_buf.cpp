/*************************************************
* Pipe Output Buffer Source file                 *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/out_buf.h>
#include <botan/secqueue.h>
#include <iostream>

namespace Botan {

/*************************************************
* Read data from a message                       *
*************************************************/
u32bit Output_Buffers::read(byte output[], u32bit length, u32bit msg)
   {
   std::tr1::shared_ptr<SecureQueue> q = get(msg);
   if(q.get())
      return q->read(output, length);
   return 0;
   }

/*************************************************
* Peek at data in a message                      *
*************************************************/
u32bit Output_Buffers::peek(byte output[], u32bit length,
                            u32bit stream_offset, u32bit msg) const
   {
   std::tr1::shared_ptr<SecureQueue> q = get(msg);
   if(q.get())
      return q->peek(output, length, stream_offset);
   return 0;
   }

/*************************************************
* Check available bytes in a message             *
*************************************************/
u32bit Output_Buffers::remaining(u32bit msg) const
   {
   std::tr1::shared_ptr<SecureQueue> q = get(msg);
   if(q.get()) {
      return q->size();
   }
   return 0;
   }

/*************************************************
* Add a new output queue                         *
*************************************************/
void Output_Buffers::add(SharedPtrConverter<SecureQueue> queue)
   {
   if(!queue.get_shared().get())
      throw Internal_Error("Output_Buffers::add: Argument was NULL");

   if(buffers.size() == buffers.max_size())
      throw Internal_Error("Output_Buffers::add: No more room in container");

   buffers.push_back(queue.get_shared());
   }

/*************************************************
* Retire old output queues                       *
*************************************************/
void Output_Buffers::retire()
   {
   while(buffers.size())
      {
      if(buffers[0].get() == 0 || buffers[0]->size() == 0)
         {
         buffers[0].reset();
         buffers.pop_front();
         ++offset;
         }
      else
         break;
      }
   }

/*************************************************
* Get a particular output queue                  *
*************************************************/
std::tr1::shared_ptr<SecureQueue> Output_Buffers::get(u32bit msg) const
   {
   if(msg < offset)
      return std::tr1::shared_ptr<SecureQueue>();
   if(msg > message_count())
      throw Internal_Error("Output_Buffers::get: msg > size");

   return buffers[msg-offset];
   }

/*************************************************
* Return the total number of messages            *
*************************************************/
u32bit Output_Buffers::message_count() const
   {
   return (buffers.size() + offset);
   }

/*************************************************
* Output_Buffers Constructor                     *
*************************************************/
Output_Buffers::Output_Buffers()
   {
   offset = 0;
   }

/*************************************************
* Output_Buffers Destructor                      *
*************************************************/
Output_Buffers::~Output_Buffers()
   {

   }

}
