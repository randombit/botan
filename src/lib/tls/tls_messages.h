/*
* TLS Messages
* (C) 2004-2011,2015 Jack Lloyd
*     2016 Matthias Gierlings
*     2021 Elektrobit Automotive GmbH
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_MESSAGES_H_
#define BOTAN_TLS_MESSAGES_H_

#include <botan/tls_algos.h>
#include <botan/tls_handshake_msg.h>
#include <botan/tls_session_id.h>
#include <botan/tls_signature_scheme.h>
#include <botan/tls_version.h>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace Botan {

class Public_Key;
class Credentials_Manager;
class X509_Certificate;
class X509_DN;
class RandomNumberGenerator;

class OctetString;
typedef OctetString SymmetricKey;

namespace OCSP {
class Response;
}

namespace TLS {

enum class Extension_Code : uint16_t;

class Session_Manager;
class Extensions;
class Handshake_IO;
class Handshake_State;
class Hello_Retry_Request;
class Callbacks;
class Cipher_State;
class Session_with_Handle;
class Session;
class Policy;

std::vector<uint8_t> make_hello_random(RandomNumberGenerator& rng, Callbacks& cb, const Policy& policy);

/**
* DTLS Hello Verify Request
*/
class BOTAN_UNSTABLE_API Hello_Verify_Request final : public Handshake_Message {
   public:
      std::vector<uint8_t> serialize() const override;

      Handshake_Type type() const override { return Handshake_Type::HelloVerifyRequest; }

      const std::vector<uint8_t>& cookie() const { return m_cookie; }

      explicit Hello_Verify_Request(const std::vector<uint8_t>& buf);

      Hello_Verify_Request(const std::vector<uint8_t>& client_hello_bits,
                           std::string_view client_identity,
                           const SymmetricKey& secret_key);

   private:
      std::vector<uint8_t> m_cookie;
};

class Client_Hello_Internal;

/**
* Client Hello Message
*/
class BOTAN_UNSTABLE_API Client_Hello : public Handshake_Message {
   public:
      Client_Hello(const Client_Hello&) = delete;
      Client_Hello& operator=(const Client_Hello&) = delete;
      Client_Hello(Client_Hello&&) noexcept;
      Client_Hello& operator=(Client_Hello&&) noexcept;

      ~Client_Hello() override;

      Handshake_Type type() const override;

      /**
       * Return the version indicated in the ClientHello.
       * This may differ from the version indicated in the supported_versions extension.
       *
       * See RFC 8446 4.1.2:
       *   TLS 1.3, the client indicates its version preferences in the
       *   "supported_versions" extension (Section 4.2.1) and the
       *   legacy_version field MUST be set to 0x0303, which is the version
       *   number for TLS 1.2.
       */
      Protocol_Version legacy_version() const;

      const std::vector<uint8_t>& random() const;

      const Session_ID& session_id() const;

      const std::vector<uint16_t>& ciphersuites() const;

      bool offered_suite(uint16_t ciphersuite) const;

      std::vector<Signature_Scheme> signature_schemes() const;
      std::vector<Signature_Scheme> certificate_signature_schemes() const;

      std::vector<Group_Params> supported_ecc_curves() const;

      // This returns any groups in the FFDHE range
      std::vector<Group_Params> supported_dh_groups() const;

      std::vector<Protocol_Version> supported_versions() const;

      std::string sni_hostname() const;

      bool supports_alpn() const;

      bool sent_signature_algorithms() const;

      std::vector<std::string> next_protocols() const;

      std::vector<uint16_t> srtp_profiles() const;

      std::vector<uint8_t> serialize() const override;

      const std::vector<uint8_t>& cookie() const;

      std::vector<uint8_t> cookie_input_data() const;

      std::set<Extension_Code> extension_types() const;

      const Extensions& extensions() const;

   protected:
      Client_Hello();
      explicit Client_Hello(std::unique_ptr<Client_Hello_Internal> data);

      const std::vector<uint8_t>& compression_methods() const;

   protected:
      std::unique_ptr<Client_Hello_Internal> m_data;  // NOLINT(*non-private-member-variable*)
};

class BOTAN_UNSTABLE_API Client_Hello_12 final : public Client_Hello {
   public:
      class Settings final {
         public:
            explicit Settings(const Protocol_Version version, std::string_view hostname = "") :
                  m_new_session_version(version), m_hostname(hostname) {}

            Protocol_Version protocol_version() const { return m_new_session_version; }

            const std::string& hostname() const { return m_hostname; }

         private:
            const Protocol_Version m_new_session_version;
            const std::string m_hostname;
      };

   public:
      explicit Client_Hello_12(const std::vector<uint8_t>& buf);

      Client_Hello_12(Handshake_IO& io,
                      Handshake_Hash& hash,
                      const Policy& policy,
                      Callbacks& cb,
                      RandomNumberGenerator& rng,
                      const std::vector<uint8_t>& reneg_info,
                      const Settings& client_settings,
                      const std::vector<std::string>& next_protocols);

      Client_Hello_12(Handshake_IO& io,
                      Handshake_Hash& hash,
                      const Policy& policy,
                      Callbacks& cb,
                      RandomNumberGenerator& rng,
                      const std::vector<uint8_t>& reneg_info,
                      const Session_with_Handle& session_and_handle,
                      const std::vector<std::string>& next_protocols);

   protected:
      friend class Client_Hello_13;  // to allow construction by Client_Hello_13::parse()
      explicit Client_Hello_12(std::unique_ptr<Client_Hello_Internal> data);

   public:
      using Client_Hello::compression_methods;
      using Client_Hello::random;

      bool prefers_compressed_ec_points() const;

      bool secure_renegotiation() const;

      std::vector<uint8_t> renegotiation_info() const;

      bool supports_session_ticket() const;

      Session_Ticket session_ticket() const;

      std::optional<Session_Handle> session_handle() const;

      bool supports_extended_master_secret() const;

      bool supports_cert_status_message() const;

      bool supports_encrypt_then_mac() const;

      void update_hello_cookie(const Hello_Verify_Request& hello_verify);

   private:
      void add_tls12_supported_groups_extensions(const Policy& policy);
};

class Server_Hello_Internal;

/**
* Server Hello Message
*/
class BOTAN_UNSTABLE_API Server_Hello : public Handshake_Message {
   public:
      Server_Hello(const Server_Hello&) = delete;
      Server_Hello& operator=(const Server_Hello&) = delete;
      Server_Hello(Server_Hello&&) noexcept;
      Server_Hello& operator=(Server_Hello&&) noexcept;

      ~Server_Hello() override;

      std::vector<uint8_t> serialize() const override;

      Handshake_Type type() const override;

      // methods available in both subclasses' interface
      uint16_t ciphersuite() const;
      const Extensions& extensions() const;
      const Session_ID& session_id() const;

      virtual Protocol_Version selected_version() const = 0;

   protected:
      explicit Server_Hello(std::unique_ptr<Server_Hello_Internal> data);

      // methods used internally and potentially exposed by one of the subclasses
      std::set<Extension_Code> extension_types() const;
      const std::vector<uint8_t>& random() const;
      uint8_t compression_method() const;
      Protocol_Version legacy_version() const;

   protected:
      std::unique_ptr<Server_Hello_Internal> m_data;  // NOLINT(*non-private-member-variable*)
};

class BOTAN_UNSTABLE_API Server_Hello_12 final : public Server_Hello {
   public:
      class Settings final {
         public:
            Settings(Session_ID new_session_id,
                     Protocol_Version new_session_version,
                     uint16_t ciphersuite,
                     bool offer_session_ticket) :
                  m_new_session_id(std::move(new_session_id)),
                  m_new_session_version(new_session_version),
                  m_ciphersuite(ciphersuite),
                  m_offer_session_ticket(offer_session_ticket) {}

            const Session_ID& session_id() const { return m_new_session_id; }

            Protocol_Version protocol_version() const { return m_new_session_version; }

            uint16_t ciphersuite() const { return m_ciphersuite; }

            bool offer_session_ticket() const { return m_offer_session_ticket; }

         private:
            const Session_ID m_new_session_id;
            Protocol_Version m_new_session_version;
            uint16_t m_ciphersuite;
            bool m_offer_session_ticket;
      };

      Server_Hello_12(Handshake_IO& io,
                      Handshake_Hash& hash,
                      const Policy& policy,
                      Callbacks& cb,
                      RandomNumberGenerator& rng,
                      const std::vector<uint8_t>& secure_reneg_info,
                      const Client_Hello_12& client_hello,
                      const Settings& settings,
                      std::string_view next_protocol);

      Server_Hello_12(Handshake_IO& io,
                      Handshake_Hash& hash,
                      const Policy& policy,
                      Callbacks& cb,
                      RandomNumberGenerator& rng,
                      const std::vector<uint8_t>& secure_reneg_info,
                      const Client_Hello_12& client_hello,
                      const Session& resumed_session,
                      bool offer_session_ticket,
                      std::string_view next_protocol);

      explicit Server_Hello_12(const std::vector<uint8_t>& buf);

   protected:
      friend class Server_Hello_13;  // to allow construction by Server_Hello_13::parse()
      explicit Server_Hello_12(std::unique_ptr<Server_Hello_Internal> data);

   public:
      using Server_Hello::compression_method;
      using Server_Hello::extension_types;
      using Server_Hello::legacy_version;
      using Server_Hello::random;

      /**
       * @returns the selected version as indicated in the legacy_version field
       */
      Protocol_Version selected_version() const override;

      bool secure_renegotiation() const;

      std::vector<uint8_t> renegotiation_info() const;

      std::string next_protocol() const;

      bool supports_extended_master_secret() const;

      bool supports_encrypt_then_mac() const;

      bool supports_certificate_status_message() const;

      bool supports_session_ticket() const;

      uint16_t srtp_profile() const;
      bool prefers_compressed_ec_points() const;

      /**
       * Return desired downgrade version indicated by hello random, if any.
       */
      std::optional<Protocol_Version> random_signals_downgrade() const;
};

/**
* Certificate Status (RFC 6066)
*/
class BOTAN_UNSTABLE_API Certificate_Status : public Handshake_Message {
   public:
      Handshake_Type type() const final { return Handshake_Type::CertificateStatus; }

      //std::shared_ptr<const OCSP::Response> response() const { return m_response; }

      const std::vector<uint8_t>& response() const { return m_response; }

      explicit Certificate_Status(const std::vector<uint8_t>& buf, Connection_Side from);

      explicit Certificate_Status(std::vector<uint8_t> raw_response_bytes);

      std::vector<uint8_t> serialize() const final;

   private:
      std::vector<uint8_t> m_response;
};

class BOTAN_UNSTABLE_API Certificate_Verify : public Handshake_Message {
   public:
      Handshake_Type type() const override { return Handshake_Type::CertificateVerify; }

      Signature_Scheme signature_scheme() const { return m_scheme; }

      explicit Certificate_Verify(const std::vector<uint8_t>& buf);
      Certificate_Verify() = default;

      std::vector<uint8_t> serialize() const override;

   protected:
      std::vector<uint8_t> m_signature;  // NOLINT(*non-private-member-variable*)
      Signature_Scheme m_scheme;         // NOLINT(*non-private-member-variable*)
};

/**
* Finished Message
*/
class BOTAN_UNSTABLE_API Finished : public Handshake_Message {
   public:
      explicit Finished(const std::vector<uint8_t>& buf) : m_verification_data(buf) {}

      Handshake_Type type() const override { return Handshake_Type::Finished; }

      std::vector<uint8_t> verify_data() const { return m_verification_data; }

      std::vector<uint8_t> serialize() const override { return m_verification_data; }

   protected:
      using Handshake_Message::Handshake_Message;
      std::vector<uint8_t> m_verification_data;  // NOLINT(*non-private-member-variable*)
};

}  // namespace TLS

}  // namespace Botan

#endif
