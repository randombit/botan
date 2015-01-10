/*
* TLS Heartbeats
* (C) 2012,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
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

   m_padding = reader.get_remaining();

   if(m_padding.size() < 16)
      throw Decoding_Error("Invalid heartbeat padding");
   }

Heartbeat_Message::Heartbeat_Message(Type type,
                                     const byte payload[],
                                     size_t payload_len,
                                     const std::vector<byte>& padding) :
   m_type(type),
   m_payload(payload, payload + payload_len),
   m_padding(padding)
   {
   if(payload_len >= 64*1024)
      throw std::runtime_error("Heartbeat payload too long");
   if(m_padding.size() < 16)
      throw std::runtime_error("Invalid heartbeat padding length");
   }

std::vector<byte> Heartbeat_Message::contents() const
   {
   //std::vector<byte> send_buf(3 + m_payload.size() + 16);
   std::vector<byte> send_buf;
   send_buf.reserve(3 + m_payload.size() + m_padding.size());

   send_buf.push_back(m_type);
   send_buf.push_back(get_byte<u16bit>(0, m_payload.size()));
   send_buf.push_back(get_byte<u16bit>(1, m_payload.size()));
   send_buf += m_payload;
   send_buf += m_padding;

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
