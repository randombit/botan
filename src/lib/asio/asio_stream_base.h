#ifndef BOTAN_ASIO_STREAM_BASE_H_
#define BOTAN_ASIO_STREAM_BASE_H_

#include <botan/auto_rng.h>
#include <botan/tls_client.h>
#include <botan/tls_server.h>

namespace Botan {

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
         : channel_(core_,
                    sessionManager,
                    credentialsManager,
                    policy,
                    rng_,
                    serverInfo)
         {
         }

      StreamBase(const StreamBase&) = delete;
      StreamBase& operator=(const StreamBase&) = delete;

   protected:
      Botan::StreamCore    core_;
      Botan::AutoSeeded_RNG rng_;
      Botan::TLS::Client    channel_;
   };

template <>
class StreamBase<Botan::TLS::Server>
   {
   public:
      StreamBase(Botan::TLS::Session_Manager& sessionManager,
                 Botan::Credentials_Manager& credentialsManager,
                 const Botan::TLS::Policy& policy = Botan::TLS::Strict_Policy{})
         : channel_(core_, sessionManager, credentialsManager, policy, rng_)
         {
         }

      StreamBase(const StreamBase&) = delete;
      StreamBase& operator=(const StreamBase&) = delete;

   protected:
      Botan::StreamCore    core_;
      Botan::AutoSeeded_RNG rng_;
      Botan::TLS::Server    channel_;
   };

}  // namespace botan

#endif
