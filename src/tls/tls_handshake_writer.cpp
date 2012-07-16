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

std::vector<byte> Stream_Handshake_Writer::send(Handshake_Message& msg)
   {
   const std::vector<byte> buf = msg.serialize();
   std::vector<byte> send_buf(4);

   const size_t buf_size = buf.size();

   send_buf[0] = msg.type();

   for(size_t i = 1; i != 4; ++i)
     send_buf[i] = get_byte<u32bit>(i, buf_size);

   send_buf += buf;

   m_writer.send(HANDSHAKE, &send_buf[0], send_buf.size());

   return send_buf;
   }

}

}
