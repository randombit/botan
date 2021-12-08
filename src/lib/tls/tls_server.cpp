/*
* TLS Server
* (C) 2004-2011,2012,2016 Jack Lloyd
*     2016 Matthias Gierlings
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_server.h>
#include <botan/tls_messages.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_server_impl_12.h>
#include <botan/internal/tls_server_impl.h>
#include <botan/tls_magic.h>

namespace Botan {

namespace TLS {

/*
* TLS Server Constructor
*/
Server::Server(Callbacks& callbacks,
               Session_Manager& session_manager,
               Credentials_Manager& creds,
               const Policy& policy,
               RandomNumberGenerator& rng,
               bool is_datagram,
               size_t io_buf_sz) :
   m_impl(std::make_unique<Server_Impl_12>(callbacks, session_manager, creds, policy,
                                           rng, is_datagram,io_buf_sz))
   {
   }

Server::~Server() = default;

size_t Server::received_data(const uint8_t buf[], size_t buf_size)
   {
   return m_impl->channel().received_data(buf, buf_size);
   }

bool Server::is_active() const
   {
   return m_impl->channel().is_active();
   }

bool Server::is_closed() const
   {
   return m_impl->channel().is_closed();
   }

std::vector<X509_Certificate> Server::peer_cert_chain() const
   {
   return m_impl->channel().peer_cert_chain();
   }

SymmetricKey Server::key_material_export(const std::string& label,
      const std::string& context,
      size_t length) const
   {
   return m_impl->channel().key_material_export(label, context, length);
   }

void Server::renegotiate(bool force_full_renegotiation)
   {
   m_impl->channel().renegotiate(force_full_renegotiation);
   }

bool Server::secure_renegotiation_supported() const
   {
   return m_impl->channel().secure_renegotiation_supported();
   }

void Server::send(const uint8_t buf[], size_t buf_size)
   {
   m_impl->channel().send(buf, buf_size);
   }

void Server::send_alert(const Alert& alert)
   {
   m_impl->channel().send_alert(alert);
   }

void Server::send_warning_alert(Alert::Type type)
   {
   m_impl->channel().send_warning_alert(type);
   }

void Server::send_fatal_alert(Alert::Type type)
   {
   m_impl->channel().send_fatal_alert(type);
   }

void Server::close()
   {
   m_impl->channel().close();
   }

bool Server::timeout_check()
   {
   return m_impl->channel().timeout_check();
   }

std::string Server::next_protocol() const
   {
   return m_impl->next_protocol();
   }

std::string Server::application_protocol() const
   {
   return m_impl->application_protocol();
   }
}

}
