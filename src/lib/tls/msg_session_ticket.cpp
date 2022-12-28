/*
* Session Tickets
* (C) 2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/loadstor.h>

#include <botan/tls_exceptn.h>

#include <span>

namespace Botan::TLS {

New_Session_Ticket_12::New_Session_Ticket_12(Handshake_IO& io,
                                             Handshake_Hash& hash,
                                             Session_Ticket ticket,
                                             std::chrono::seconds lifetime) :
   m_ticket_lifetime_hint(lifetime),
   m_ticket(std::move(ticket))
   {
   hash.update(io.send(*this));
   }

New_Session_Ticket_12::New_Session_Ticket_12(Handshake_IO& io,
                                       Handshake_Hash& hash)
   {
   hash.update(io.send(*this));
   }

New_Session_Ticket_12::New_Session_Ticket_12(const std::vector<uint8_t>& buf)
   {
   if(buf.size() < 6)
      throw Decoding_Error("Session ticket message too short to be valid");

   TLS_Data_Reader reader("SessionTicket", buf);

   m_ticket_lifetime_hint = std::chrono::seconds(reader.get_uint32_t());
   m_ticket = Session_Ticket(reader.get_range<uint8_t>(2, 0, 65535));
   reader.assert_done();
   }

namespace {

template <typename lifetime_t = uint32_t>
void store_lifetime(std::span<uint8_t> sink, std::chrono::seconds lifetime)
   {
   BOTAN_ARG_CHECK(lifetime.count() >= 0 && lifetime.count() <= std::numeric_limits<lifetime_t>::max(),
                   "Ticket lifetime is out of range");
   store_be(static_cast<lifetime_t>(lifetime.count()), sink.data());
   }

}

std::vector<uint8_t> New_Session_Ticket_12::serialize() const
   {
   std::vector<uint8_t> buf(4);
   store_be(static_cast<uint32_t>(m_ticket_lifetime_hint.count()), buf.data());
   append_tls_length_value(buf, m_ticket.get(), 2);
   return buf;
   }

#if defined (BOTAN_HAS_TLS_13)

New_Session_Ticket_13::New_Session_Ticket_13(const std::vector<uint8_t>& buf,
                                             Connection_Side from)
   {
   TLS_Data_Reader reader("New_Session_Ticket_13", buf);

   m_ticket_lifetime_hint = std::chrono::seconds(reader.get_uint32_t());

   // RFC 8446 4.6.1
   //    Servers MUST NOT use any value [of ticket_lifetime] greater than 604800
   //    seconds (7 days).
   if(m_ticket_lifetime_hint > std::chrono::days(7))
      {
      throw TLS_Exception(Alert::IllegalParameter,
                          "Received a session ticket with lifetime longer than one week.");
      }

   m_ticket_age_add = reader.get_uint32_t();
   m_ticket_nonce = reader.get_tls_length_value(1);
   m_ticket = Session_Ticket(reader.get_tls_length_value(2));

   m_extensions.deserialize(reader, from, type());

   // RFC 8446 4.6.1
   //    The sole extension currently defined for NewSessionTicket is
   //    "early_data", indicating that the ticket may be used to send 0-RTT
   //    data [...]. Clients MUST ignore unrecognized extensions.
   if(m_extensions.contains_implemented_extensions_other_than({Extension_Code::EarlyData}))
      {
      throw TLS_Exception(Alert::IllegalParameter,
                          "NewSessionTicket message contained unexpected extension");
      }

   reader.assert_done();
   }

std::optional<uint32_t> New_Session_Ticket_13::early_data_byte_limit() const
   {
   if(!m_extensions.has<EarlyDataIndication>())
      return std::nullopt;

   const EarlyDataIndication* ext = m_extensions.get<EarlyDataIndication>();
   BOTAN_ASSERT_NOMSG(ext->max_early_data_size().has_value());
   return ext->max_early_data_size().value();
   }

std::vector<uint8_t> New_Session_Ticket_13::serialize() const
   {
   // TODO: might be needed once TLS 1.3 server is implemented
   throw Not_Implemented("serializing New_Session_Ticket_13 is NYI");
   }

#endif

}
