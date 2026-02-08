/*
* Session Tickets
* (C) 2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages_12.h>

#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_reader.h>

namespace Botan::TLS {

New_Session_Ticket_12::New_Session_Ticket_12(Handshake_IO& io,
                                             Handshake_Hash& hash,
                                             Session_Ticket ticket,
                                             uint32_t lifetime) :
      m_ticket_lifetime_hint(lifetime), m_ticket(std::move(ticket)) {
   hash.update(io.send(*this));
}

New_Session_Ticket_12::New_Session_Ticket_12(Handshake_IO& io, Handshake_Hash& hash) {
   hash.update(io.send(*this));
}

New_Session_Ticket_12::New_Session_Ticket_12(const std::vector<uint8_t>& buf) {
   if(buf.size() < 6) {
      throw Decoding_Error("Session ticket message too short to be valid");
   }

   TLS_Data_Reader reader("SessionTicket", buf);

   m_ticket_lifetime_hint = reader.get_uint32_t();
   m_ticket = Session_Ticket(reader.get_range<uint8_t>(2, 0, 65535));
   reader.assert_done();
}

std::vector<uint8_t> New_Session_Ticket_12::serialize() const {
   std::vector<uint8_t> buf(4);
   store_be(m_ticket_lifetime_hint, buf.data());
   append_tls_length_value(buf, m_ticket.get(), 2);
   return buf;
}

}  // namespace Botan::TLS
