/*
* Session Tickets
* (C) 2021-2022 Jack Lloyd
*     2021 Elektrobit Automotive GmbH
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages_13.h>

#include <botan/tls_callbacks.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_extensions_13.h>
#include <botan/tls_session.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/tls_reader.h>

#include <span>

namespace Botan::TLS {

namespace {

template <typename lifetime_t = uint32_t>
void store_lifetime(std::span<uint8_t> sink, std::chrono::seconds lifetime) {
   BOTAN_ARG_CHECK(lifetime.count() >= 0 && lifetime.count() <= std::numeric_limits<lifetime_t>::max(),
                   "Ticket lifetime is out of range");
   store_be(static_cast<lifetime_t>(lifetime.count()), sink.data());
}

}  // namespace

New_Session_Ticket_13::New_Session_Ticket_13(Ticket_Nonce nonce,
                                             const Session& session,
                                             const Session_Handle& handle,
                                             Callbacks& callbacks) :
      m_ticket_lifetime_hint(session.lifetime_hint()),
      m_ticket_age_add(session.session_age_add()),
      m_ticket_nonce(std::move(nonce)),
      m_handle(handle.opaque_handle()) {
   callbacks.tls_modify_extensions(m_extensions, Connection_Side::Server, type());
}

New_Session_Ticket_13::New_Session_Ticket_13(const std::vector<uint8_t>& buf, Connection_Side from) {
   TLS_Data_Reader reader("New_Session_Ticket_13", buf);

   m_ticket_lifetime_hint = std::chrono::seconds(reader.get_uint32_t());

   // RFC 8446 4.6.1
   //    Servers MUST NOT use any value [of ticket_lifetime] greater than 604800
   //    seconds (7 days).
   if(m_ticket_lifetime_hint > std::chrono::days(7)) {
      throw TLS_Exception(Alert::IllegalParameter, "Received a session ticket with lifetime longer than one week.");
   }

   m_ticket_age_add = reader.get_uint32_t();
   m_ticket_nonce = Ticket_Nonce(reader.get_tls_length_value(1));
   m_handle = Opaque_Session_Handle(reader.get_tls_length_value(2));

   m_extensions.deserialize(reader, from, type());

   // RFC 8446 4.6.1
   //    The sole extension currently defined for NewSessionTicket is
   //    "early_data", indicating that the ticket may be used to send 0-RTT
   //    data [...]. Clients MUST ignore unrecognized extensions.
   if(m_extensions.contains_implemented_extensions_other_than({Extension_Code::EarlyData})) {
      throw TLS_Exception(Alert::IllegalParameter, "NewSessionTicket message contained unexpected extension");
   }

   reader.assert_done();
}

std::optional<uint32_t> New_Session_Ticket_13::early_data_byte_limit() const {
   if(!m_extensions.has<EarlyDataIndication>()) {
      return std::nullopt;
   }

   const EarlyDataIndication* ext = m_extensions.get<EarlyDataIndication>();
   BOTAN_ASSERT_NOMSG(ext->max_early_data_size().has_value());
   return ext->max_early_data_size();
}

std::vector<uint8_t> New_Session_Ticket_13::serialize() const {
   std::vector<uint8_t> result(8);

   store_lifetime(std::span(result.data(), 4), m_ticket_lifetime_hint);
   store_be(m_ticket_age_add, result.data() + 4);
   append_tls_length_value(result, m_ticket_nonce.get(), 1);
   append_tls_length_value(result, m_handle.get(), 2);

   // TODO: re-evaluate this construction when reworking message marshalling
   if(m_extensions.empty()) {
      result.push_back(0x00);
      result.push_back(0x00);
   } else {
      result += m_extensions.serialize(Connection_Side::Server);
   }

   return result;
}

}  // namespace Botan::TLS
