/*
* Handshake Message Writer
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_handshake_writer.h>
#include <botan/internal/tls_messages.h>
#include <botan/tls_record.h>
#include <botan/exceptn.h>

namespace Botan {

namespace TLS {

namespace {

void store_be24(byte* out, size_t val)
   {
   out[0] = get_byte<u32bit>(1, val);
   out[1] = get_byte<u32bit>(2, val);
   out[2] = get_byte<u32bit>(3, val);
   }

}

std::vector<byte>
Stream_Handshake_Writer::format(const std::vector<byte>& msg,
                                Handshake_Type type)
   {
   std::vector<byte> send_buf(4 + msg.size());

   const size_t buf_size = msg.size();

   send_buf[0] = type;

   store_be24(&send_buf[1], buf_size);

   copy_mem(&send_buf[4], &msg[0], msg.size());

   return send_buf;
   }

std::vector<byte> Stream_Handshake_Writer::send(Handshake_Message& msg)
   {
   const std::vector<byte> buf = format(msg.serialize(), msg.type());

   m_writer.send(HANDSHAKE, &buf[0], buf.size());

   return buf;
   }

}

}
