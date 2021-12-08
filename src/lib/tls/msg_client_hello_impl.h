/*
* TLS Client Hello Message interface
* (C) 2004-2011,2015 Jack Lloyd
*     2016 Matthias Gierlings
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MSG_CLIENT_HELLO_IMPL_H_
#define BOTAN_MSG_CLIENT_HELLO_IMPL_H_

#include <botan/tls_messages.h>
#include <botan/tls_extensions.h>
#include <botan/tls_handshake_msg.h>
#include <vector>
#include <string>
#include <set>

namespace Botan {

namespace TLS {

class Session;
class Handshake_IO;
class Handshake_State;
class Callbacks;
class Policy;

/**
* Interface of pimpl for Client Hello Message
*/
class Client_Hello_Impl : public Handshake_Message
   {
   public:
      explicit Client_Hello_Impl() = default;

      Client_Hello_Impl(Handshake_IO& io,
                        Handshake_Hash& hash,
                        const Policy& policy,
                        Callbacks& cb,
                        RandomNumberGenerator& rng,
                        const std::vector<uint8_t>& reneg_info,
                        const Client_Hello::Settings& client_settings,
                        const std::vector<std::string>& next_protocols);

      Client_Hello_Impl(Handshake_IO& io,
                        Handshake_Hash& hash,
                        const Policy& policy,
                        Callbacks& cb,
                        RandomNumberGenerator& rng,
                        const std::vector<uint8_t>& reneg_info,
                        const Session& resumed_session,
                        const std::vector<std::string>& next_protocols);

      explicit Client_Hello_Impl(const std::vector<uint8_t>& buf);

      Handshake_Type type() const override;

      Protocol_Version version() const;

      virtual std::vector<Protocol_Version> supported_versions() const;

      const std::vector<uint8_t>& random() const;

      const std::vector<uint8_t>& session_id() const;

      const std::vector<uint8_t>& compression_methods() const;

      const std::vector<uint16_t>& ciphersuites() const;

      virtual bool offered_suite(uint16_t ciphersuite) const;

      virtual std::vector<Signature_Scheme> signature_schemes() const;

      virtual std::vector<Group_Params> supported_ecc_curves() const;

      virtual std::vector<Group_Params> supported_dh_groups() const;

      virtual bool prefers_compressed_ec_points() const;

      virtual std::string sni_hostname() const;

      virtual bool secure_renegotiation() const;

      virtual std::vector<uint8_t> renegotiation_info() const;

      virtual bool supports_session_ticket() const;

      virtual std::vector<uint8_t> session_ticket() const;

      virtual bool supports_alpn() const;

      virtual bool supports_extended_master_secret() const;

      virtual bool supports_cert_status_message() const;

      virtual bool supports_encrypt_then_mac() const;

      virtual bool sent_signature_algorithms() const;

      virtual std::vector<std::string> next_protocols() const;

      virtual std::vector<uint16_t> srtp_profiles() const;

      virtual void update_hello_cookie(const Hello_Verify_Request& hello_verify);

      virtual const std::vector<uint8_t>& cookie() const;

      virtual std::vector<uint8_t> cookie_input_data() const;

      std::set<Handshake_Extension_Type> extension_types() const;

      const Extensions& extensions() const;

      std::vector<uint8_t> serialize() const override;

   protected:
      Protocol_Version m_version;
      std::vector<uint8_t> m_session_id;
      std::vector<uint8_t> m_random;
      std::vector<uint16_t> m_suites;
      std::vector<uint8_t> m_comp_methods;
      Extensions m_extensions;

      std::vector<uint8_t> m_hello_cookie; // DTLS only
      std::vector<uint8_t> m_cookie_input_bits; // DTLS only
   };

}

}

#endif
