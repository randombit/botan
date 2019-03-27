/*
 * TLS Context
 * (C) 2018-2019 Jack Lloyd
 *     2018-2019 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_ASIO_TLS_CONTEXT_H_
#define BOTAN_ASIO_TLS_CONTEXT_H_

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_HAS_BOOST_ASIO)

#include <boost/version.hpp>
#if BOOST_VERSION > 106600

#include <botan/credentials_manager.h>
#include <botan/rng.h>
#include <botan/tls_policy.h>
#include <botan/tls_server_info.h>
#include <botan/tls_session_manager.h>

namespace Botan {
namespace TLS {

struct Context
   {
   Credentials_Manager*   credentialsManager;
   RandomNumberGenerator* randomNumberGenerator;
   Session_Manager*       sessionManager;
   Policy*                policy;
   Server_Information     serverInfo;
   };

}  // namespace TLS
}  // namespace Botan

#endif  // BOOST_VERSION
#endif  // BOTAN_HAS_TLS && BOTAN_HAS_BOOST_ASIO
#endif  // BOTAN_ASIO_TLS_CONTEXT_H_
