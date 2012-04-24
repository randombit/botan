/*
* TLS Handshake Reader
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_handshake_reader.h>
#include <botan/exceptn.h>

namespace Botan {

namespace TLS {

void Stream_Handshake_Reader::add_input(const byte record[],
                                        size_t record_size)
   {
   m_queue.write(record, record_size);
   }

bool Stream_Handshake_Reader::empty() const
   {
   return m_queue.empty();
   }

bool Stream_Handshake_Reader::have_full_record() const
   {
   if(m_queue.size() >= 4)
      {
      byte head[4] = { 0 };
      m_queue.peek(head, 4);

      const size_t length = make_u32bit(0, head[1], head[2], head[3]);

      return (m_queue.size() >= length + 4);
      }

   return false;
   }

std::pair<Handshake_Type, MemoryVector<byte> > Stream_Handshake_Reader::get_next_record()
   {
   if(m_queue.size() >= 4)
      {
      byte head[4] = { 0 };
      m_queue.peek(head, 4);

      const size_t length = make_u32bit(0, head[1], head[2], head[3]);

      if(m_queue.size() >= length + 4)
         {
         Handshake_Type type = static_cast<Handshake_Type>(head[0]);
         MemoryVector<byte> contents(length);
         m_queue.read(head, 4); // discard
         m_queue.read(&contents[0], contents.size());

         return std::make_pair(type, contents);
         }
      }

   throw Internal_Error("Stream_Handshake_Reader::get_next_record called without a full record");
   }

}

}
