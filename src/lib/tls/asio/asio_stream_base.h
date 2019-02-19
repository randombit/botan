/*
* TLS Stream Helper
* (C) 2018-2019 Jack Lloyd
*     2018-2019 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_STREAM_BASE_H_
#define BOTAN_ASIO_STREAM_BASE_H_

#include <botan/auto_rng.h>
#include <botan/tls_client.h>
#include <botan/tls_server.h>

namespace Botan {

namespace TLS {

template <class Channel>
class StreamBase
   {
   };

template <>
class StreamBase<Botan::TLS::Client>
   {
   public:
      StreamBase(Botan::TLS::Session_Manager& sessionManager,
                 Botan::Credentials_Manager& credentialsManager,
                 const Botan::TLS::Policy& policy = Botan::TLS::Strict_Policy{},
                 const Botan::TLS::Server_Information& serverInfo =
                    Botan::TLS::Server_Information{})
         : m_channel(m_core,
                     sessionManager,
                     credentialsManager,
                     policy,
                     m_rng,
                     serverInfo)
         {
         }

      StreamBase(const StreamBase&) = delete;
      StreamBase& operator=(const StreamBase&) = delete;

   protected:
      Botan::TLS::StreamCore m_core;
      Botan::AutoSeeded_RNG  m_rng;
      Botan::TLS::Client     m_channel;
   };

template <>
class StreamBase<Botan::TLS::Server>
   {
   public:
      StreamBase(Botan::TLS::Session_Manager& sessionManager,
                 Botan::Credentials_Manager& credentialsManager,
                 const Botan::TLS::Policy& policy = Botan::TLS::Strict_Policy{})
         : m_channel(m_core, sessionManager, credentialsManager, policy, m_rng)
         {
         }

      StreamBase(const StreamBase&) = delete;
      StreamBase& operator=(const StreamBase&) = delete;

   protected:
      Botan::TLS::StreamCore m_core;
      Botan::AutoSeeded_RNG  m_rng;
      Botan::TLS::Server     m_channel;
   };

}  // namespace TLS

}  // namespace Botan

#endif
