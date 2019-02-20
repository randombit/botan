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
#include <botan/asio_error.h>

namespace Botan {

namespace TLS {

enum handshake_type
   {
   client,
   server
   };


/* Base class for all Botan::TLS::Stream implementations.
 *
 *
 */
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

      using handshake_type = Botan::TLS::handshake_type;

   protected:
      void validate_handshake_type(handshake_type type)
         {
         if(type != handshake_type::client)
            {
            throw Invalid_Argument("wrong handshake_type");
            }
         }

      bool validate_handshake_type(handshake_type type, boost::system::error_code& ec)
         {
         if(type != handshake_type::client)
            {
            ec = make_error_code(Botan::TLS::error::invalid_argument);
            return false;
            }

         return true;
         }

      Botan::TLS::StreamCore m_core;
      Botan::AutoSeeded_RNG  m_rng;
      Botan::TLS::Client     m_channel;
   };

}  // namespace TLS

}  // namespace Botan

#endif
