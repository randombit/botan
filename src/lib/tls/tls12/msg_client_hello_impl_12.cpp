/*
* TLS Hello Request and Client Hello Messages
* (C) 2004-2011,2015,2016 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>
#include <botan/tls_alert.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_policy.h>
#include <botan/tls_session.h>
#include <botan/rng.h>
#include <botan/hash.h>

#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_session_key.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/msg_client_hello_impl_12.h>

namespace Botan {

namespace TLS {

/*
* Create a new Client Hello message
*/
Client_Hello_Impl_12::Client_Hello_Impl_12(Handshake_IO& io,
                           Handshake_Hash& hash,
                           const Policy& policy,
                           Callbacks& cb,
                           RandomNumberGenerator& rng,
                           const std::vector<uint8_t>& reneg_info,
                           const Client_Hello::Settings& client_settings,
                           const std::vector<std::string>& next_protocols) :
   Client_Hello_Impl(io, hash, policy, cb, rng, reneg_info, client_settings, next_protocols)
   {
   }

/*
* Create a new Client Hello message (session resumption case)
*/
Client_Hello_Impl_12::Client_Hello_Impl_12(Handshake_IO& io,
                           Handshake_Hash& hash,
                           const Policy& policy,
                           Callbacks& cb,
                           RandomNumberGenerator& rng,
                           const std::vector<uint8_t>& reneg_info,
                           const Session& session,
                           const std::vector<std::string>& next_protocols) :
   Client_Hello_Impl(io, hash, policy, cb, rng, reneg_info, session, next_protocols)
   {
   }

Client_Hello_Impl_12::Client_Hello_Impl_12(const std::vector<uint8_t>& buf) :
   Client_Hello_Impl(buf)
   {
   }

}

}
