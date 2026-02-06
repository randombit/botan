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

/**
 * Basic implementation of Client_Hello from TLS 1.2. The full implementation
 * is in Client_Hello_12 in the tls12 module. This is meant to be used by the
 * TLS 1.3 implementation to parse, validate and understand a downgrade request.
 */
class BOTAN_UNSTABLE_API Client_Hello_12_Shim : public Client_Hello {
   public:
      explicit Client_Hello_12_Shim(const std::vector<uint8_t>& buf);

   protected:
      using Client_Hello::Client_Hello;

      friend class Client_Hello_13;  // to allow construction by Client_Hello_13::parse()
      explicit Client_Hello_12_Shim(std::unique_ptr<Client_Hello_Internal> data);
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

/**
 * Basic implementation of Server_Hello from TLS 1.2. The full implementation
 * is in Server_Hello_12 in the tls12 module. This is meant to be used by the
 * TLS 1.3 implementation to parse, validate and understand a downgrade request.
 */
class BOTAN_UNSTABLE_API Server_Hello_12_Shim : public Server_Hello {
   public:
      explicit Server_Hello_12_Shim(const std::vector<uint8_t>& buf);

   protected:
      friend class Server_Hello_13;  // to allow construction by Server_Hello_13::parse()
      explicit Server_Hello_12_Shim(std::unique_ptr<Server_Hello_Internal> data);

   public:
      /**
       * @returns the selected version as indicated in the legacy_version field
       */
      Protocol_Version selected_version() const final;

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
