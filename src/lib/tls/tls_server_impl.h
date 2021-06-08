/*
* TLS Server
* (C) 2004-2011 Jack Lloyd
*     2016 Matthias Gierlings
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_SERVER_IMPL_H_
#define BOTAN_TLS_SERVER_IMPL_H_

#include <botan/tls_magic.h>
#include <vector>
#include <memory>
#include <string>

namespace Botan {

namespace TLS {

class Handshake_State;
class Handshake_IO;
class Channel_Impl;

/**
* Interface of pimpl for Server
*/
class Server_Impl
   {
   public:
      virtual ~Server_Impl() = default;

      explicit Server_Impl(Channel_Impl& impl) : m_impl{impl} {}

      Channel_Impl& channel() { return m_impl; }

      /**
      * Return the protocol notification set by the client (using the
      * ALPN extension) for this connection, if any. This value is not
      * tied to the session and a later renegotiation of the same
      * session can choose a new protocol.
      */
      virtual std::string next_protocol() const = 0;

      /**
      * Return the protocol notification set by the client (using the
      * ALPN extension) for this connection, if any. This value is not
      * tied to the session and a later renegotiation of the same
      * session can choose a new protocol.
      */
      virtual std::string application_protocol() const = 0;

      virtual void initiate_handshake(Handshake_State& state,
                                      bool force_full_renegotiation) = 0;

      virtual void process_handshake_msg(const Handshake_State* active_state,
                                         Handshake_State& pending_state,
                                         Handshake_Type type,
                                         const std::vector<uint8_t>& contents,
                                         bool epoch0_restart) = 0;

      virtual std::unique_ptr<Handshake_State> new_handshake_state(std::unique_ptr<Handshake_IO> io) = 0;

   private:
      Channel_Impl& m_impl;
   };
}
}

#endif
