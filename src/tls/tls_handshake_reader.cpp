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
   m_queue.insert(m_queue.end(), record, record + record_size);
   }

bool Stream_Handshake_Reader::empty() const
   {
   return m_queue.empty();
   }

bool Stream_Handshake_Reader::have_full_record() const
   {
   if(m_queue.size() >= 4)
      {
      const size_t length = make_u32bit(0,
                                        m_queue[1],
                                        m_queue[2],
                                        m_queue[3]);

      return (m_queue.size() >= length + 4);
      }

   return false;
   }

std::pair<Handshake_Type, std::vector<byte> > Stream_Handshake_Reader::get_next_record()
   {
   if(m_queue.size() >= 4)
      {
      const size_t length = make_u32bit(0,
                                        m_queue[1],
                                        m_queue[2],
                                        m_queue[3]);

      if(m_queue.size() >= length + 4)
         {
         Handshake_Type type = static_cast<Handshake_Type>(m_queue[0]);

         std::vector<byte> contents(m_queue.begin() + 4,
                                    m_queue.begin() + 4 + length);

         m_queue.erase(m_queue.begin(), m_queue.begin() + 4 + length);

         return std::make_pair(type, contents);
         }
      }

   throw Internal_Error("Stream_Handshake_Reader::get_next_record called without a full record");
   }

}

}
