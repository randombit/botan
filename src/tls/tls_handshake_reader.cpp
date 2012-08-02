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

namespace {

inline size_t load_be24(const byte q[3])
   {
   return make_u32bit(0,
                      q[0],
                      q[1],
                      q[2]);
   }

}


void Stream_Handshake_Reader::add_input(const byte rec_type,
                                        const byte record[],
                                        size_t record_size)
   {
   if(rec_type == HANDSHAKE)
      {
      m_queue.insert(m_queue.end(), record, record + record_size);
      }
   else if(rec_type == CHANGE_CIPHER_SPEC)
      {
      if(record_size != 1 || record[0] != 1)
         throw Decoding_Error("Invalid ChangeCipherSpec");

      const byte ccs_hs[] = { HANDSHAKE_CCS, 0, 0, 0 };
      m_queue.insert(m_queue.end(), ccs_hs, ccs_hs + sizeof(ccs_hs));
      }
   else
      throw Decoding_Error("Unknown message type in handshake processing");
   }

bool Stream_Handshake_Reader::empty() const
   {
   return m_queue.empty();
   }

bool Stream_Handshake_Reader::have_full_record() const
   {
   if(m_queue.size() >= 4)
      {
      const size_t length = load_be24(&m_queue[1]);

      return (m_queue.size() >= length + 4);
      }

   return false;
   }

std::pair<Handshake_Type, std::vector<byte> > Stream_Handshake_Reader::get_next_record()
   {
   if(m_queue.size() >= 4)
      {
      const size_t length = load_be24(&m_queue[1]);

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
