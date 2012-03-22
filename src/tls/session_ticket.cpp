/*
* Session Tickets
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_extensions.h>
#include <botan/internal/tls_reader.h>
#include <botan/tls_record.h>
#include <botan/loadstor.h>

namespace Botan {

namespace TLS {

New_Session_Ticket::New_Session_Ticket(const MemoryRegion<byte>& buf) :
   m_ticket_lifetime_hint(0)
   {
   if(buf.size() >= 4)
      {
      m_ticket_lifetime_hint = load_be<u32bit>(&buf[0], 0);
      m_ticket.resize(buf.size() - 4);
      copy_mem(&m_ticket[0], &buf[4], buf.size() - 4);
      }
   }

MemoryVector<byte> New_Session_Ticket::serialize() const
   {
   MemoryVector<byte> buf(4 + m_ticket.size());
   store_be(m_ticket_lifetime_hint, &buf[0]);
   copy_mem(&buf[4], &m_ticket[0], m_ticket.size());
   return buf;
   }

}

}
