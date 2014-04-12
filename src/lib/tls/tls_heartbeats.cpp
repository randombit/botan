/*
* TLS Heartbeats
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_heartbeats.h>
#include <botan/internal/tls_extensions.h>
#include <botan/internal/tls_reader.h>
#include <botan/tls_exceptn.h>

namespace Botan {

namespace TLS {

Heartbeat_Message::Heartbeat_Message(const std::vector<byte>& buf)
   {
   TLS_Data_Reader reader("Heartbeat", buf);

   const byte type = reader.get_byte();

   if(type != 1 && type != 2)
      throw TLS_Exception(Alert::ILLEGAL_PARAMETER,
                          "Unknown heartbeat message type");

   m_type = static_cast<Type>(type);

   m_payload = reader.get_range<byte>(2, 0, 16*1024);

   // padding follows and is ignored
   }

Heartbeat_Message::Heartbeat_Message(Type type,
                                     const byte payload[],
                                     size_t payload_len) :
   m_type(type),
   m_payload(payload, payload + payload_len)
   {
   }

std::vector<byte> Heartbeat_Message::contents() const
   {
   std::vector<byte> send_buf(3 + m_payload.size() + 16);
   send_buf[0] = m_type;
   send_buf[1] = get_byte<u16bit>(0, m_payload.size());
   send_buf[2] = get_byte<u16bit>(1, m_payload.size());
   copy_mem(&send_buf[3], &m_payload[0], m_payload.size());
   // leave padding as all zeros

   return send_buf;
   }

std::vector<byte> Heartbeat_Support_Indicator::serialize() const
   {
   std::vector<byte> heartbeat(1);
   heartbeat[0] = (m_peer_allowed_to_send ? 1 : 2);
   return heartbeat;
   }

Heartbeat_Support_Indicator::Heartbeat_Support_Indicator(TLS_Data_Reader& reader,
                                                         u16bit extension_size)
   {
   if(extension_size != 1)
      throw Decoding_Error("Strange size for heartbeat extension");

   const byte code = reader.get_byte();

   if(code != 1 && code != 2)
      throw TLS_Exception(Alert::ILLEGAL_PARAMETER,
                          "Unknown heartbeat code " + std::to_string(code));

   m_peer_allowed_to_send = (code == 1);
   }

}

}
