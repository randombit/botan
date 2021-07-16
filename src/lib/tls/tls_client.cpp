/*
* TLS Client
* (C) 2004-2011,2012,2015,2016 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_client.h>
#include <botan/tls_messages.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_client_impl.h>
#include <botan/internal/tls_client_impl_12.h>
#include <botan/internal/tls_endpoint_factory.h>

#if defined(BOTAN_HAS_TLS_13)
#include <botan/internal/tls_client_impl_13.h>
#endif

#include <iterator>
#include <sstream>

namespace Botan {

namespace TLS {

/*
* TLS Client Constructor
*/
Client::Client(Callbacks& callbacks,
               Session_Manager& session_manager,
               Credentials_Manager& creds,
               const Policy& policy,
               RandomNumberGenerator& rng,
               const Server_Information& info,
               const Protocol_Version& offer_version,
               const std::vector<std::string>& next_protocols,
               size_t io_buf_sz) :
   m_impl(
#if defined(BOTAN_HAS_TLS_13)
      offer_version == Protocol_Version::TLS_V13 ?
      TLS_Endpoint_Factory::create<Client_Impl, Protocol_Version::TLS_V13>(
         callbacks, session_manager, creds, policy,
         rng, info, offer_version, next_protocols, io_buf_sz) :
#endif
      TLS_Endpoint_Factory::create<Client_Impl, Protocol_Version::TLS_V12>(
         callbacks, session_manager, creds, policy,
         rng, info, offer_version, next_protocols, io_buf_sz))

   {
   }

Client::~Client() = default;

size_t Client::received_data(const uint8_t buf[], size_t buf_size)
   {
   return m_impl->channel().received_data(buf, buf_size);
   }

bool Client::is_active() const
   {
   return m_impl->channel().is_active();
   }

bool Client::is_closed() const
   {
   return m_impl->channel().is_closed();
   }

std::vector<X509_Certificate> Client::peer_cert_chain() const
   {
   return m_impl->channel().peer_cert_chain();
   }

SymmetricKey Client::key_material_export(const std::string& label,
      const std::string& context,
      size_t length) const
   {
   return m_impl->channel().key_material_export(label, context, length);
   }

void Client::renegotiate(bool force_full_renegotiation)
   {
   m_impl->channel().renegotiate(force_full_renegotiation);
   }

bool Client::secure_renegotiation_supported() const
   {
   return m_impl->channel().secure_renegotiation_supported();
   }

void Client::send(const uint8_t buf[], size_t buf_size)
   {
   m_impl->channel().send(buf, buf_size);
   }

void Client::send_alert(const Alert& alert)
   {
   m_impl->channel().send_alert(alert);
   }

void Client::send_warning_alert(Alert::Type type)
   {
   m_impl->channel().send_warning_alert(type);
   }

void Client::send_fatal_alert(Alert::Type type)
   {
   m_impl->channel().send_fatal_alert(type);
   }

void Client::close()
   {
   m_impl->channel().close();
   }

bool Client::timeout_check()
   {
   return m_impl->channel().timeout_check();
   }

std::string Client::application_protocol() const
   {
   return m_impl->application_protocol();
   }

}

}
