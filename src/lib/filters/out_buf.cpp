/*
* Pipe Output Buffer
* (C) 1999-2007,2011 Jack Lloyd
*     2012 Markus Wanner
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/out_buf.h>

#include <botan/internal/secqueue.h>

namespace Botan {

/*
* Read data from a message
*/
size_t Output_Buffers::read(uint8_t output[], size_t length, Pipe::message_id msg) {
   SecureQueue* q = get(msg);
   if(q) {
      return q->read(output, length);
   }
   return 0;
}

/*
* Peek at data in a message
*/
size_t Output_Buffers::peek(uint8_t output[], size_t length, size_t stream_offset, Pipe::message_id msg) const {
   SecureQueue* q = get(msg);
   if(q) {
      return q->peek(output, length, stream_offset);
   }
   return 0;
}

/*
* Check available bytes in a message
*/
size_t Output_Buffers::remaining(Pipe::message_id msg) const {
   SecureQueue* q = get(msg);
   if(q) {
      return q->size();
   }
   return 0;
}

/*
* Return the total bytes of a message that have already been read.
*/
size_t Output_Buffers::get_bytes_read(Pipe::message_id msg) const {
   SecureQueue* q = get(msg);
   if(q) {
      return q->get_bytes_read();
   }
   return 0;
}

/*
* Add a new output queue
*/
void Output_Buffers::add(SecureQueue* queue) {
   BOTAN_ASSERT(queue, "queue was provided");

   BOTAN_ASSERT(m_buffers.size() < m_buffers.max_size(), "Room was available in container");

   m_buffers.push_back(std::unique_ptr<SecureQueue>(queue));
}

/*
* Retire old output queues
*/
void Output_Buffers::retire() {
   for(auto& buf : m_buffers) {
      if(buf && buf->empty()) {
         buf.reset();
      }
   }

   while(!m_buffers.empty() && !m_buffers[0]) {
      m_buffers.pop_front();
      m_offset = m_offset + Pipe::message_id(1);
   }
}

/*
* Get a particular output queue
*/
SecureQueue* Output_Buffers::get(Pipe::message_id msg) const {
   if(msg < m_offset) {
      return nullptr;
   }

   BOTAN_ASSERT(msg < message_count(), "Message number is in range");

   return m_buffers[msg - m_offset].get();
}

/*
* Return the total number of messages
*/
Pipe::message_id Output_Buffers::message_count() const {
   return (m_offset + m_buffers.size());
}

/*
* Output_Buffers Constructor
*/
Output_Buffers::Output_Buffers() {
   m_offset = 0;
}

}  // namespace Botan
