/*
* TLS Server Hello Impl for (D)TLS 1.2
* (C) 2004-2011,2015,2016,2019 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_callbacks.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/msg_server_hello_impl_12.h>

namespace Botan {

namespace TLS {

// New session case
Server_Hello_Impl_12::Server_Hello_Impl_12(Handshake_IO& io,
                                           Handshake_Hash& hash,
                                           const Policy& policy,
                                           Callbacks& cb,
                                           RandomNumberGenerator& rng,
                                           const std::vector<uint8_t>& reneg_info,
                                           const Client_Hello& client_hello,
                                           const Server_Hello::Settings& server_settings,
                                           const std::string next_protocol) :
   Server_Hello_Impl(policy, rng, client_hello, server_settings, next_protocol)
   {
   Ciphersuite c = Ciphersuite::by_id(m_ciphersuite);

   if(c.cbc_ciphersuite() && client_hello.supports_encrypt_then_mac() && policy.negotiate_encrypt_then_mac())
      {
      m_extensions.add(new Encrypt_then_MAC);
      }

   if(c.ecc_ciphersuite() && client_hello.extension_types().count(TLSEXT_EC_POINT_FORMATS))
      {
      m_extensions.add(new Supported_Point_Formats(policy.use_ecc_point_compression()));
      }

   if(client_hello.secure_renegotiation())
      {
      m_extensions.add(new Renegotiation_Extension(reneg_info));
      }

   if(client_hello.supports_session_ticket() && server_settings.offer_session_ticket())
      {
      m_extensions.add(new Session_Ticket());
      }

   if(m_version.is_datagram_protocol())
      {
      const std::vector<uint16_t> server_srtp = policy.srtp_profiles();
      const std::vector<uint16_t> client_srtp = client_hello.srtp_profiles();

      if(!server_srtp.empty() && !client_srtp.empty())
         {
         uint16_t shared = 0;
         // always using server preferences for now
         for(auto s_srtp : server_srtp)
            for(auto c_srtp : client_srtp)
               {
               if(shared == 0 && s_srtp == c_srtp)
                  shared = s_srtp;
               }

         if(shared)
            {
            m_extensions.add(new SRTP_Protection_Profiles(shared));
            }
         }
      }

   cb.tls_modify_extensions(m_extensions, SERVER);

   hash.update(io.send(*this));
   }

// Resuming
Server_Hello_Impl_12::Server_Hello_Impl_12(Handshake_IO& io,
                                           Handshake_Hash& hash,
                                           const Policy& policy,
                                           Callbacks& cb,
                                           RandomNumberGenerator& rng,
                                           const std::vector<uint8_t>& reneg_info,
                                           const Client_Hello& client_hello,
                                           Session& resumed_session,
                                           bool offer_session_ticket,
                                           const std::string& next_protocol) :
   Server_Hello_Impl(policy, rng, client_hello, resumed_session, next_protocol)
   {
   if(client_hello.supports_encrypt_then_mac() && policy.negotiate_encrypt_then_mac())
      {
      Ciphersuite c = resumed_session.ciphersuite();
      if(c.cbc_ciphersuite())
         {
         m_extensions.add(new Encrypt_then_MAC);
         }
      }

   if(resumed_session.ciphersuite().ecc_ciphersuite() && client_hello.extension_types().count(TLSEXT_EC_POINT_FORMATS))
      {
      m_extensions.add(new Supported_Point_Formats(policy.use_ecc_point_compression()));
      }

   if(client_hello.secure_renegotiation())
      {
      m_extensions.add(new Renegotiation_Extension(reneg_info));
      }

   if(client_hello.supports_session_ticket() && offer_session_ticket)
      {
      m_extensions.add(new Session_Ticket());
      }

   cb.tls_modify_extensions(m_extensions, SERVER);

   hash.update(io.send(*this));
   }

/*
* Deserialize a Server Hello message
*/
Server_Hello_Impl_12::Server_Hello_Impl_12(const std::vector<uint8_t>& buf) :
   Server_Hello_Impl(buf)
   {
   // Common implementation is enough, as received Server_Hello shall be read correctly independent of the version
   }


}

}
