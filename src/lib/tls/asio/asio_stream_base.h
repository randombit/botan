/*
* TLS Stream Helper
* (C) 2018-2019 Jack Lloyd
*     2018-2019 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_STREAM_BASE_H_
#define BOTAN_ASIO_STREAM_BASE_H_

#include <botan/build.h>

#include <boost/version.hpp>
#if BOOST_VERSION >= 106600

#include <botan/asio_context.h>
#include <botan/asio_error.h>
#include <botan/internal/asio_stream_core.h>
#include <botan/tls_client.h>
#include <botan/tls_magic.h>

namespace Botan {

namespace TLS {

/** Base class for all Botan::TLS::Stream implementations.
 *
 * This template must be specialized for all the Botan::TLS::Channel to be used.
 * Currently it only supports the Botan::TLS::Client channel that impersonates
 * the client-side of a TLS connection.
 *
 * TODO: create a Botan::TLS::Server specialization
 */
template <class Channel>
class StreamBase
   {
   };

template <>
class StreamBase<Botan::TLS::Client>
   {
   public:
      StreamBase(Context& context)
         : m_channel(m_core,
                     *context.sessionManager,
                     *context.credentialsManager,
                     *context.policy,
                     *context.randomNumberGenerator,
                     context.serverInfo)
         {
         }

      StreamBase(const StreamBase&) = delete;
      StreamBase& operator=(const StreamBase&) = delete;

   protected:
      //! \brief validate the connection side (OpenSSL compatibility)
      void validate_connection_side(Connection_Side side)
         {
         if(side != CLIENT)
            {
            throw Invalid_Argument("wrong connection_side");
            }
         }

      //! \brief validate the connection side (OpenSSL compatibility)
      bool validate_connection_side(Connection_Side side, boost::system::error_code& ec)
         {
         if(side != CLIENT)
            {
            ec = Botan::TLS::error::invalid_argument;
            return false;
            }

         return true;
         }

      Botan::TLS::StreamCore m_core;
      Botan::TLS::Client     m_channel;
   };

}  // namespace TLS

}  // namespace Botan

#endif // BOOST_VERSION
#endif // BOTAN_ASIO_STREAM_BASE_H_
