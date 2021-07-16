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
   m_extensions.add(new Session_Ticket());

   if(policy.negotiate_encrypt_then_mac())
      m_extensions.add(new Encrypt_then_MAC);

   m_extensions.add(new Renegotiation_Extension(reneg_info));

   m_extensions.add(new Supported_Versions(m_version, policy));

   if(client_settings.hostname() != "")
      m_extensions.add(new Server_Name_Indicator(client_settings.hostname()));

   if(policy.support_cert_status_message())
      m_extensions.add(new Certificate_Status_Request({}, {}));

   if(reneg_info.empty() && !next_protocols.empty())
      m_extensions.add(new Application_Layer_Protocol_Notification(next_protocols));

   m_extensions.add(new Signature_Algorithms(policy.acceptable_signature_schemes()));

   if(m_version.is_datagram_protocol())
      m_extensions.add(new SRTP_Protection_Profiles(policy.srtp_profiles()));

   auto supported_groups = std::make_unique<Supported_Groups>(policy.key_exchange_groups());

   if(supported_groups->ec_groups().size() > 0)
      {
      m_extensions.add(new Supported_Point_Formats(policy.use_ecc_point_compression()));
      }

   m_extensions.add(supported_groups.release());

   cb.tls_modify_extensions(m_extensions, CLIENT);

   hash.update(io.send(*this));
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
   if(!value_exists(m_suites, session.ciphersuite_code()))
      m_suites.push_back(session.ciphersuite_code());

   m_extensions.add(new Renegotiation_Extension(reneg_info));
   m_extensions.add(new Server_Name_Indicator(session.server_info().hostname()));
   m_extensions.add(new Session_Ticket(session.session_ticket()));

   if(policy.support_cert_status_message())
      m_extensions.add(new Certificate_Status_Request({}, {}));

   auto supported_groups = std::make_unique<Supported_Groups>(policy.key_exchange_groups());

   if(supported_groups->ec_groups().size() > 0)
      {
      m_extensions.add(new Supported_Point_Formats(policy.use_ecc_point_compression()));
      }

   m_extensions.add(supported_groups.release());

   if(session.supports_encrypt_then_mac())
      m_extensions.add(new Encrypt_then_MAC);

   m_extensions.add(new Signature_Algorithms(policy.acceptable_signature_schemes()));

   if(reneg_info.empty() && !next_protocols.empty())
      m_extensions.add(new Application_Layer_Protocol_Notification(next_protocols));

   cb.tls_modify_extensions(m_extensions, CLIENT);

   hash.update(io.send(*this));
   }

Client_Hello_Impl_12::Client_Hello_Impl_12(const std::vector<uint8_t>& buf) :
   Client_Hello_Impl(buf)
   {
   // Common implementation is enough, as received Client_Hello shall be read correctly independent of the version
   }

}

}
