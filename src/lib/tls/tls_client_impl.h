/*
* TLS Client
* (C) 2004-2011 Jack Lloyd
*     2016 Matthias Gierlings
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CLIENT_IMPL_H_
#define BOTAN_TLS_CLIENT_IMPL_H_

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
* Interface of pimpl for Client
*/
class Client_Impl
   {
   public:
      virtual ~Client_Impl() = default;

      explicit Client_Impl(Channel_Impl& impl) : m_impl{impl} {}

      Channel_Impl& channel() { return m_impl; }

      /**
      * @return network protocol as advertised by the TLS server, if server sent the ALPN extension
      */
      virtual std::string application_protocol() const = 0;

      virtual void initiate_handshake(
         Handshake_State& state,
         bool force_full_renegotiation) = 0;

      virtual std::unique_ptr<Handshake_State> new_handshake_state(std::unique_ptr<Handshake_IO> io) = 0;

   private:
      Channel_Impl& m_impl;
   };
}
}

#endif
