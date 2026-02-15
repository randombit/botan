/*
* TLS Extensions
* (C) 2011,2012,2016,2018,2019 Jack Lloyd
* (C) 2016 Juraj Somorovsky
* (C) 2016 Matthias Gierlings
* (C) 2021 Elektrobit Automotive GmbH
* (C) 2022 René Meusel, Hannes Rantzsch - neXenio GmbH
* (C) 2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_EXTENSIONS_H_
#define BOTAN_TLS_EXTENSIONS_H_

#include <botan/assert.h>
#include <botan/tls_algos.h>
#include <botan/tls_magic.h>
#include <botan/tls_signature_scheme.h>
#include <botan/tls_version.h>

#include <memory>
#include <set>

namespace Botan {

class RandomNumberGenerator;
class Credentials_Manager;
class X509_DN;

namespace TLS {

class Policy;
class TLS_Data_Reader;

enum class Extension_Code : uint16_t {
   ServerNameIndication = 0,
   CertificateStatusRequest = 5,

   SupportedGroups = 10,
   EcPointFormats = 11,  // TLS 1.2 exclusive
   SignatureAlgorithms = 13,
   CertSignatureAlgorithms = 50,
   UseSrtp = 14,
   ApplicationLayerProtocolNegotiation = 16,

   // SignedCertificateTimestamp          = 18,  // NYI

   // RFC 7250 (Raw Public Keys in TLS)
   ClientCertificateType = 19,
   ServerCertificateType = 20,

   EncryptThenMac = 22,        // TLS 1.2 exclusive
   ExtendedMasterSecret = 23,  // TLS 1.2 exclusive

   RecordSizeLimit = 28,

   SessionTicket = 35,  // TLS 1.2 exclusive

   SupportedVersions = 43,

   PresharedKey = 41,            // TLS 1.3 exclusive
   EarlyData = 42,               // TLS 1.3 exclusive
   Cookie = 44,                  // TLS 1.3 exclusive
   PskKeyExchangeModes = 45,     // TLS 1.3 exclusive
   CertificateAuthorities = 47,  // TLS 1.3 exclusive
   KeyShare = 51,                // TLS 1.3 exclusive

   SafeRenegotiation = 65281,  // TLS 1.2 exclusive
};

/**
* Base class representing a TLS extension of some kind
*/
class BOTAN_UNSTABLE_API Extension /* NOLINT(*-special-member-functions) */ {
   public:
      /**
      * @return code number of the extension
      */
      virtual Extension_Code type() const = 0;

      /**
      * @return serialized binary for the extension
      */
      virtual std::vector<uint8_t> serialize(Connection_Side whoami) const = 0;

      /**
      * @return if we should encode this extension or not
      */
      virtual bool empty() const = 0;

      /**
       * @return true if this extension is known and implemented by Botan
       */
      virtual bool is_implemented() const { return true; }

      virtual ~Extension() = default;
};

/**
* Server Name Indicator extension (RFC 3546)
*/
class BOTAN_UNSTABLE_API Server_Name_Indicator final : public Extension {
   public:
      static Extension_Code static_type() { return Extension_Code::ServerNameIndication; }

      Extension_Code type() const override { return static_type(); }

      explicit Server_Name_Indicator(std::string_view host_name) : m_sni_host_name(host_name) {}

      Server_Name_Indicator(TLS_Data_Reader& reader, uint16_t extension_size);

      std::string host_name() const { return m_sni_host_name; }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return false; }

      static bool hostname_acceptable_for_sni(std::string_view hostname);

   private:
      std::string m_sni_host_name;
};

/**
* ALPN (RFC 7301)
*/
class BOTAN_UNSTABLE_API Application_Layer_Protocol_Notification final : public Extension {
   public:
      static Extension_Code static_type() { return Extension_Code::ApplicationLayerProtocolNegotiation; }

      Extension_Code type() const override { return static_type(); }

      const std::vector<std::string>& protocols() const { return m_protocols; }

      std::string single_protocol() const;

      /**
      * Single protocol, used by server
      */
      explicit Application_Layer_Protocol_Notification(std::string_view protocol) :
            m_protocols(1, std::string(protocol)) {}

      /**
      * List of protocols, used by client
      */
      explicit Application_Layer_Protocol_Notification(const std::vector<std::string>& protocols) :
            m_protocols(protocols) {}

      Application_Layer_Protocol_Notification(TLS_Data_Reader& reader, uint16_t extension_size, Connection_Side from);

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return m_protocols.empty(); }

   private:
      std::vector<std::string> m_protocols;
};

/**
 * RFC 7250
 * Base class for 'client_certificate_type' and 'server_certificate_type' extensions.
 */
class BOTAN_UNSTABLE_API Certificate_Type_Base : public Extension {
   public:
      /**
       * Called by the client to advertise support for a number of cert types.
       */
      explicit Certificate_Type_Base(std::vector<Certificate_Type> supported_cert_types);

   protected:
      /**
       * Called by the server to select a cert type to be used in the handshake.
       */
      Certificate_Type_Base(const Certificate_Type_Base& certificate_type_from_client,
                            const std::vector<Certificate_Type>& server_preference);

   public:
      Certificate_Type_Base(TLS_Data_Reader& reader, uint16_t extension_size, Connection_Side from);

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      void validate_selection(const Certificate_Type_Base& from_server) const;
      Certificate_Type selected_certificate_type() const;

      bool empty() const override {
         // RFC 7250 4.1
         //    If the client has no remaining certificate types to send in the
         //    client hello, other than the default X.509 type, it MUST omit the
         //    entire client[/server]_certificate_type extension [...].
         return m_from == Connection_Side::Client && m_certificate_types.size() == 1 &&
                m_certificate_types.front() == Certificate_Type::X509;
      }

   private:
      std::vector<Certificate_Type> m_certificate_types;
      Connection_Side m_from;
};

class BOTAN_UNSTABLE_API Client_Certificate_Type final : public Certificate_Type_Base {
   public:
      using Certificate_Type_Base::Certificate_Type_Base;

      /**
       * Creates the Server Hello extension from the received client preferences.
       */
      Client_Certificate_Type(const Client_Certificate_Type& cct, const Policy& policy);

      static Extension_Code static_type() { return Extension_Code::ClientCertificateType; }

      Extension_Code type() const override { return static_type(); }
};

class BOTAN_UNSTABLE_API Server_Certificate_Type final : public Certificate_Type_Base {
   public:
      using Certificate_Type_Base::Certificate_Type_Base;

      /**
       * Creates the Server Hello extension from the received client preferences.
       */
      Server_Certificate_Type(const Server_Certificate_Type& sct, const Policy& policy);

      static Extension_Code static_type() { return Extension_Code::ServerCertificateType; }

      Extension_Code type() const override { return static_type(); }
};

/**
* Supported Groups Extension (RFC 7919)
*/
class BOTAN_UNSTABLE_API Supported_Groups final : public Extension {
   public:
      static Extension_Code static_type() { return Extension_Code::SupportedGroups; }

      Extension_Code type() const override { return static_type(); }

      const std::vector<Group_Params>& groups() const;

      // Returns the list of groups we recognize as ECDH curves
      std::vector<Group_Params> ec_groups() const;

      // Returns the list of any groups in the FFDHE range
      std::vector<Group_Params> dh_groups() const;

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      explicit Supported_Groups(const std::vector<Group_Params>& groups);

      Supported_Groups(TLS_Data_Reader& reader, uint16_t extension_size);

      bool empty() const override { return m_groups.empty(); }

   private:
      std::vector<Group_Params> m_groups;
};

/**
* Signature Algorithms Extension for TLS 1.2 (RFC 5246)
*/
class BOTAN_UNSTABLE_API Signature_Algorithms final : public Extension {
   public:
      static Extension_Code static_type() { return Extension_Code::SignatureAlgorithms; }

      Extension_Code type() const override { return static_type(); }

      const std::vector<Signature_Scheme>& supported_schemes() const { return m_schemes; }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return m_schemes.empty(); }

      explicit Signature_Algorithms(std::vector<Signature_Scheme> schemes) : m_schemes(std::move(schemes)) {}

      Signature_Algorithms(TLS_Data_Reader& reader, uint16_t extension_size);

   private:
      std::vector<Signature_Scheme> m_schemes;
};

/**
* Signature_Algorithms_Cert for TLS 1.3 (RFC 8446)
*
* RFC 8446 4.2.3
*    TLS 1.3 provides two extensions for indicating which signature algorithms
*    may be used in digital signatures.  The "signature_algorithms_cert"
*    extension applies to signatures in certificates, and the
*    "signature_algorithms" extension, which originally appeared in TLS 1.2,
*    applies to signatures in CertificateVerify messages.
*
* RFC 8446 4.2.3
*    TLS 1.2 implementations SHOULD also process this extension.
*/
class BOTAN_UNSTABLE_API Signature_Algorithms_Cert final : public Extension {
   public:
      static Extension_Code static_type() { return Extension_Code::CertSignatureAlgorithms; }

      Extension_Code type() const override { return static_type(); }

      const std::vector<Signature_Scheme>& supported_schemes() const { return m_schemes; }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return m_schemes.empty(); }

      explicit Signature_Algorithms_Cert(std::vector<Signature_Scheme> schemes) : m_schemes(std::move(schemes)) {}

      Signature_Algorithms_Cert(TLS_Data_Reader& reader, uint16_t extension_size);

   private:
      std::vector<Signature_Scheme> m_schemes;
};

/**
* Used to indicate SRTP algorithms for DTLS (RFC 5764)
*/
class BOTAN_UNSTABLE_API SRTP_Protection_Profiles final : public Extension {
   public:
      static Extension_Code static_type() { return Extension_Code::UseSrtp; }

      Extension_Code type() const override { return static_type(); }

      const std::vector<uint16_t>& profiles() const { return m_pp; }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return m_pp.empty(); }

      explicit SRTP_Protection_Profiles(const std::vector<uint16_t>& pp) : m_pp(pp) {}

      explicit SRTP_Protection_Profiles(uint16_t pp) : m_pp(1, pp) {}

      SRTP_Protection_Profiles(TLS_Data_Reader& reader, uint16_t extension_size);

   private:
      std::vector<uint16_t> m_pp;
};

class Certificate_Status_Request_Internal;

/**
* Certificate Status Request (RFC 6066)
*/
class BOTAN_UNSTABLE_API Certificate_Status_Request final : public Extension /* NOLINT(*-special-member-functions) */ {
   public:
      static Extension_Code static_type() { return Extension_Code::CertificateStatusRequest; }

      Extension_Code type() const override { return static_type(); }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return false; }

      const std::vector<uint8_t>& get_responder_id_list() const;
      const std::vector<uint8_t>& get_request_extensions() const;
      const std::vector<uint8_t>& get_ocsp_response() const;

      // TLS 1.2 Server generated version: empty
      Certificate_Status_Request();

      // TLS 1.2 Client version, both lists can be empty
      Certificate_Status_Request(std::vector<uint8_t> ocsp_responder_ids,
                                 std::vector<std::vector<uint8_t>> ocsp_key_ids);

      // TLS 1.3 version
      explicit Certificate_Status_Request(std::vector<uint8_t> response);

      Certificate_Status_Request(TLS_Data_Reader& reader,
                                 uint16_t extension_size,
                                 Handshake_Type message_type,
                                 Connection_Side from);

      ~Certificate_Status_Request() override;

   private:
      std::unique_ptr<Certificate_Status_Request_Internal> m_impl;
};

/**
* Supported Versions from RFC 8446
*/
class BOTAN_UNSTABLE_API Supported_Versions final : public Extension {
   public:
      static Extension_Code static_type() { return Extension_Code::SupportedVersions; }

      Extension_Code type() const override { return static_type(); }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return m_versions.empty(); }

      Supported_Versions(Protocol_Version version, const Policy& policy);

      explicit Supported_Versions(Protocol_Version version) { m_versions.push_back(version); }

      Supported_Versions(TLS_Data_Reader& reader, uint16_t extension_size, Connection_Side from);

      bool supports(Protocol_Version version) const;

      const std::vector<Protocol_Version>& versions() const { return m_versions; }

   private:
      std::vector<Protocol_Version> m_versions;
};

using Named_Group = Group_Params;

/**
* Record Size Limit (RFC 8449)
*
* TODO: the record size limit is currently not honored by the TLS 1.2 stack
*/
class BOTAN_UNSTABLE_API Record_Size_Limit final : public Extension {
   public:
      static Extension_Code static_type() { return Extension_Code::RecordSizeLimit; }

      Extension_Code type() const override { return static_type(); }

      explicit Record_Size_Limit(uint16_t limit);

      Record_Size_Limit(TLS_Data_Reader& reader, uint16_t extension_size, Connection_Side from);

      uint16_t limit() const { return m_limit; }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return m_limit == 0; }

   private:
      uint16_t m_limit;
};

/**
* Unknown extensions are deserialized as this type
*/
class BOTAN_UNSTABLE_API Unknown_Extension final : public Extension {
   public:
      Unknown_Extension(Extension_Code type, TLS_Data_Reader& reader, uint16_t extension_size);

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      const std::vector<uint8_t>& value() { return m_value; }

      bool empty() const override { return false; }

      Extension_Code type() const override { return m_type; }

      bool is_implemented() const override { return false; }

   private:
      Extension_Code m_type;
      std::vector<uint8_t> m_value;
};

/**
* Represents a block of extensions in a hello message
*/
class BOTAN_UNSTABLE_API Extensions final {
   public:
      std::set<Extension_Code> extension_types() const;

      const std::vector<std::unique_ptr<Extension>>& all() const { return m_extensions; }

      template <typename T>
      T* get() const {
         return dynamic_cast<T*>(get(T::static_type()));
      }

      template <typename T>
      bool has() const {
         return get<T>() != nullptr;
      }

      bool has(Extension_Code type) const { return get(type) != nullptr; }

      size_t size() const { return m_extensions.size(); }

      bool empty() const { return m_extensions.empty(); }

      void add(std::unique_ptr<Extension> extn);

      void add(Extension* extn) { add(std::unique_ptr<Extension>(extn)); }

      Extension* get(Extension_Code type) const;

      std::vector<uint8_t> serialize(Connection_Side whoami) const;

      void deserialize(TLS_Data_Reader& reader, Connection_Side from, Handshake_Type message_type);

      /**
       * @param allowed_extensions        extension types that are allowed
       * @param allow_unknown_extensions  if true, ignores unrecognized extensions
       * @returns true if this contains any extensions that are not contained in @p allowed_extensions.
       */
      bool contains_other_than(const std::set<Extension_Code>& allowed_extensions,
                               bool allow_unknown_extensions = false) const;

      /**
       * @param allowed_extensions  extension types that are allowed
       * @returns true if this contains any extensions implemented by Botan that
       *          are not contained in @p allowed_extensions.
       */
      bool contains_implemented_extensions_other_than(const std::set<Extension_Code>& allowed_extensions) const {
         return contains_other_than(allowed_extensions, true);
      }

      /**
       * Take the extension with the given type out of the extensions list.
       * Returns a nullptr if the extension didn't exist.
       */
      template <typename T>
      decltype(auto) take() {
         std::unique_ptr<T> out_ptr;

         auto ext = take(T::static_type());
         if(ext != nullptr) {
            out_ptr.reset(dynamic_cast<T*>(ext.get()));
            BOTAN_ASSERT_NOMSG(out_ptr != nullptr);
            ext.release();
         }

         return out_ptr;
      }

      /**
       * Take the extension with the given type out of the extensions list.
       * Returns a nullptr if the extension didn't exist.
       */
      std::unique_ptr<Extension> take(Extension_Code type);

      /**
      * Remove an extension from this extensions object, if it exists.
      * Returns true if the extension existed (and thus is now removed),
      * otherwise false (the extension wasn't set in the first place).
      *
      * Note: not used internally, might be used in Callbacks::tls_modify_extensions()
      */
      bool remove_extension(Extension_Code type) { return take(type) != nullptr; }

      Extensions() = default;
      Extensions(const Extensions&) = delete;
      Extensions& operator=(const Extensions&) = delete;
      Extensions(Extensions&&) = default;
      Extensions& operator=(Extensions&&) = default;
      ~Extensions();

      Extensions(TLS_Data_Reader& reader, Connection_Side side, Handshake_Type message_type) {
         deserialize(reader, side, message_type);
      }

   private:
      std::vector<std::unique_ptr<Extension>> m_extensions;
};

}  // namespace TLS

}  // namespace Botan

#endif
