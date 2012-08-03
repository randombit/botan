/*
* TLS Handshake IO
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_messages.h>
#include <botan/tls_record.h>
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

void store_be24(byte out[3], size_t val)
   {
   out[0] = get_byte<u32bit>(1, val);
   out[1] = get_byte<u32bit>(2, val);
   out[2] = get_byte<u32bit>(3, val);
   }

}

void Stream_Handshake_IO::add_input(const byte rec_type,
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

bool Stream_Handshake_IO::empty() const
   {
   return m_queue.empty();
   }

bool Stream_Handshake_IO::have_full_record() const
   {
   if(m_queue.size() >= 4)
      {
      const size_t length = load_be24(&m_queue[1]);

      return (m_queue.size() >= length + 4);
      }

   return false;
   }

std::pair<Handshake_Type, std::vector<byte> >
Stream_Handshake_IO::get_next_record()
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

   throw Internal_Error("Stream_Handshake_IO::get_next_record called without a full record");
   }

std::vector<byte>
Stream_Handshake_IO::format(const std::vector<byte>& msg,
                            Handshake_Type type)
   {
   std::vector<byte> send_buf(4 + msg.size());

   const size_t buf_size = msg.size();

   send_buf[0] = type;

   store_be24(&send_buf[1], buf_size);

   copy_mem(&send_buf[4], &msg[0], msg.size());

   return send_buf;
   }

std::vector<byte> Stream_Handshake_IO::send(Handshake_Message& msg)
   {
   const std::vector<byte> buf = format(msg.serialize(), msg.type());

   m_writer.send(HANDSHAKE, &buf[0], buf.size());

   return buf;
   }

}

}
