/*
* Session Tickets
* (C) 2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_extensions.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/loadstor.h>

namespace Botan {

namespace TLS {

New_Session_Ticket::New_Session_Ticket(Handshake_IO& io,
                                       Handshake_Hash& hash,
                                       const std::vector<byte>& ticket,
                                       u32bit lifetime) :
   m_ticket_lifetime_hint(lifetime),
   m_ticket(ticket)
   {
   hash.update(io.send(*this));
   }

New_Session_Ticket::New_Session_Ticket(Handshake_IO& io,
                                       Handshake_Hash& hash)
   {
   hash.update(io.send(*this));
   }

New_Session_Ticket::New_Session_Ticket(const std::vector<byte>& buf)
   {
   if(buf.size() < 6)
      throw Decoding_Error("Session ticket message too short to be valid");

   TLS_Data_Reader reader("SessionTicket", buf);

   m_ticket_lifetime_hint = reader.get_u32bit();
   m_ticket = reader.get_range<byte>(2, 0, 65535);
   }

std::vector<byte> New_Session_Ticket::serialize() const
   {
   std::vector<byte> buf(4);
   store_be(m_ticket_lifetime_hint, &buf[0]);
   append_tls_length_value(buf, m_ticket, 2);
   return buf;
   }

}

}
