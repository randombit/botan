/*
* TLS Extensions
* (C) 2011,2012,2016,2018,2019 Jack Lloyd
* (C) 2016 Juraj Somorovsky
* (C) 2016 Matthias Gierlings
* (C) 2021 Elektrobit Automotive GmbH
* (C) 2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_EXTENSIONS_H_
#define BOTAN_TLS_EXTENSIONS_H_

#include <botan/tls_algos.h>
#include <botan/tls_magic.h>
#include <botan/tls_version.h>
#include <botan/secmem.h>
#include <botan/pkix_types.h>
#include <botan/tls_signature_scheme.h>

#include <algorithm>
#include <optional>
#include <variant>
#include <vector>
#include <string>
#include <set>

namespace Botan {

class RandomNumberGenerator;

namespace TLS {

#if defined(BOTAN_HAS_TLS_13)
class Callbacks;

enum class PSK_Key_Exchange_Mode : uint8_t {
   PSK_KE = 0,
   PSK_DHE_KE = 1
};

#endif
class Policy;
class TLS_Data_Reader;

// This will become an enum class in a future major release
enum Handshake_Extension_Type {
   TLSEXT_SERVER_NAME_INDICATION    = 0,
   TLSEXT_CERT_STATUS_REQUEST       = 5,

   TLSEXT_CERTIFICATE_TYPES         = 9,
   TLSEXT_SUPPORTED_GROUPS          = 10,
   TLSEXT_EC_POINT_FORMATS          = 11,
   TLSEXT_SIGNATURE_ALGORITHMS      = 13,
   TLSEXT_USE_SRTP                  = 14,
   TLSEXT_ALPN                      = 16,

   // TLSEXT_SIGNED_CERTIFICATE_TIMESTAMP = 18,  // NYI

   TLSEXT_ENCRYPT_THEN_MAC          = 22,
   TLSEXT_EXTENDED_MASTER_SECRET    = 23,

   TLSEXT_RECORD_SIZE_LIMIT         = 28,

   TLSEXT_SESSION_TICKET            = 35,

   TLSEXT_SUPPORTED_VERSIONS        = 43,
#if defined(BOTAN_HAS_TLS_13)
   TLSEXT_COOKIE                    = 44,

   TLSEXT_PSK_KEY_EXCHANGE_MODES    = 45,
   TLSEXT_CERTIFICATE_AUTHORITIES   = 47,
   // TLSEXT_OID_FILTERS               = 48,  // NYI

   TLSEXT_SIGNATURE_ALGORITHMS_CERT = 50,
   TLSEXT_KEY_SHARE                 = 51,
#endif

   TLSEXT_SAFE_RENEGOTIATION     = 65281,
};

/**
* Base class representing a TLS extension of some kind
*/
class BOTAN_UNSTABLE_API Extension
   {
   public:
      /**
      * @return code number of the extension
      */
      virtual Handshake_Extension_Type type() const = 0;

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
class BOTAN_UNSTABLE_API Server_Name_Indicator final : public Extension
   {
   public:
      static Handshake_Extension_Type static_type()
         { return TLSEXT_SERVER_NAME_INDICATION; }

      Handshake_Extension_Type type() const override { return static_type(); }

      explicit Server_Name_Indicator(const std::string& host_name) :
         m_sni_host_name(host_name) {}

      Server_Name_Indicator(TLS_Data_Reader& reader,
                            uint16_t extension_size);

      std::string host_name() const { return m_sni_host_name; }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return m_sni_host_name.empty(); }
   private:
      std::string m_sni_host_name;
   };

/**
* Renegotiation Indication Extension (RFC 5746)
*/
class BOTAN_UNSTABLE_API Renegotiation_Extension final : public Extension
   {
   public:
      static Handshake_Extension_Type static_type()
         { return TLSEXT_SAFE_RENEGOTIATION; }

      Handshake_Extension_Type type() const override { return static_type(); }

      Renegotiation_Extension() = default;

      explicit Renegotiation_Extension(const std::vector<uint8_t>& bits) :
         m_reneg_data(bits) {}

      Renegotiation_Extension(TLS_Data_Reader& reader,
                             uint16_t extension_size);

      const std::vector<uint8_t>& renegotiation_info() const
         { return m_reneg_data; }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return false; } // always send this
   private:
      std::vector<uint8_t> m_reneg_data;
   };

/**
* ALPN (RFC 7301)
*/
class BOTAN_UNSTABLE_API Application_Layer_Protocol_Notification final : public Extension
   {
   public:
      static Handshake_Extension_Type static_type() { return TLSEXT_ALPN; }

      Handshake_Extension_Type type() const override { return static_type(); }

      const std::vector<std::string>& protocols() const { return m_protocols; }

      const std::string& single_protocol() const;

      /**
      * Single protocol, used by server
      */
      explicit Application_Layer_Protocol_Notification(const std::string& protocol) :
         m_protocols(1, protocol) {}

      /**
      * List of protocols, used by client
      */
      explicit Application_Layer_Protocol_Notification(const std::vector<std::string>& protocols) :
         m_protocols(protocols) {}

      Application_Layer_Protocol_Notification(TLS_Data_Reader& reader,
                                              uint16_t extension_size,
                                              Connection_Side from);

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return m_protocols.empty(); }
   private:
      std::vector<std::string> m_protocols;
   };

/**
* Session Ticket Extension (RFC 5077)
*/
class BOTAN_UNSTABLE_API Session_Ticket final : public Extension
   {
   public:
      static Handshake_Extension_Type static_type()
         { return TLSEXT_SESSION_TICKET; }

      Handshake_Extension_Type type() const override { return static_type(); }

      /**
      * @return contents of the session ticket
      */
      const std::vector<uint8_t>& contents() const { return m_ticket; }

      /**
      * Create empty extension, used by both client and server
      */
      Session_Ticket() = default;

      /**
      * Extension with ticket, used by client
      */
      explicit Session_Ticket(const std::vector<uint8_t>& session_ticket) :
         m_ticket(session_ticket) {}

      /**
      * Deserialize a session ticket
      */
      Session_Ticket(TLS_Data_Reader& reader, uint16_t extension_size);

      std::vector<uint8_t> serialize(Connection_Side) const override { return m_ticket; }

      bool empty() const override { return false; }
   private:
      std::vector<uint8_t> m_ticket;
   };


/**
* Supported Groups Extension (RFC 7919)
*/
class BOTAN_UNSTABLE_API Supported_Groups final : public Extension
   {
   public:
      static Handshake_Extension_Type static_type()
         { return TLSEXT_SUPPORTED_GROUPS; }

      Handshake_Extension_Type type() const override { return static_type(); }

      const std::vector<Group_Params>& groups() const;
      std::vector<Group_Params> ec_groups() const;
      std::vector<Group_Params> dh_groups() const;

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      explicit Supported_Groups(const std::vector<Group_Params>& groups);

      Supported_Groups(TLS_Data_Reader& reader,
                       uint16_t extension_size);

      bool empty() const override { return m_groups.empty(); }
   private:
      std::vector<Group_Params> m_groups;
   };

// previously Supported Elliptic Curves Extension (RFC 4492)
//using Supported_Elliptic_Curves = Supported_Groups;

/**
* Supported Point Formats Extension (RFC 4492)
*/
class BOTAN_UNSTABLE_API Supported_Point_Formats final : public Extension
   {
   public:
      enum ECPointFormat : uint8_t {
         UNCOMPRESSED = 0,
         ANSIX962_COMPRESSED_PRIME = 1,
         ANSIX962_COMPRESSED_CHAR2 = 2, // don't support these curves
      };

      static Handshake_Extension_Type static_type()
         { return TLSEXT_EC_POINT_FORMATS; }

      Handshake_Extension_Type type() const override { return static_type(); }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      explicit Supported_Point_Formats(bool prefer_compressed) :
         m_prefers_compressed(prefer_compressed) {}

      Supported_Point_Formats(TLS_Data_Reader& reader,
                              uint16_t extension_size);

      bool empty() const override { return false; }

      bool prefers_compressed() { return m_prefers_compressed; }

   private:
      bool m_prefers_compressed = false;
   };

/**
* Signature Algorithms Extension for TLS 1.2 (RFC 5246)
*/
class BOTAN_UNSTABLE_API Signature_Algorithms final : public Extension
   {
   public:
      static Handshake_Extension_Type static_type()
         { return TLSEXT_SIGNATURE_ALGORITHMS; }

      Handshake_Extension_Type type() const override { return static_type(); }

      const std::vector<Signature_Scheme>& supported_schemes() const { return m_schemes; }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return m_schemes.empty(); }

      explicit Signature_Algorithms(const std::vector<Signature_Scheme>& schemes) :
         m_schemes(schemes) {}

      Signature_Algorithms(TLS_Data_Reader& reader,
                           uint16_t extension_size);
   private:
      std::vector<Signature_Scheme> m_schemes;
   };

/**
* Used to indicate SRTP algorithms for DTLS (RFC 5764)
*/
class BOTAN_UNSTABLE_API SRTP_Protection_Profiles final : public Extension
   {
   public:
      static Handshake_Extension_Type static_type()
         { return TLSEXT_USE_SRTP; }

      Handshake_Extension_Type type() const override { return static_type(); }

      const std::vector<uint16_t>& profiles() const { return m_pp; }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return m_pp.empty(); }

      explicit SRTP_Protection_Profiles(const std::vector<uint16_t>& pp) : m_pp(pp) {}

      explicit SRTP_Protection_Profiles(uint16_t pp) : m_pp(1, pp) {}

      SRTP_Protection_Profiles(TLS_Data_Reader& reader, uint16_t extension_size);
   private:
      std::vector<uint16_t> m_pp;
   };

/**
* Extended Master Secret Extension (RFC 7627)
*/
class BOTAN_UNSTABLE_API Extended_Master_Secret final : public Extension
   {
   public:
      static Handshake_Extension_Type static_type()
         { return TLSEXT_EXTENDED_MASTER_SECRET; }

      Handshake_Extension_Type type() const override { return static_type(); }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return false; }

      Extended_Master_Secret() = default;

      Extended_Master_Secret(TLS_Data_Reader& reader, uint16_t extension_size);
   };

/**
* Encrypt-then-MAC Extension (RFC 7366)
*/
class BOTAN_UNSTABLE_API Encrypt_then_MAC final : public Extension
   {
   public:
      static Handshake_Extension_Type static_type()
         { return TLSEXT_ENCRYPT_THEN_MAC; }

      Handshake_Extension_Type type() const override { return static_type(); }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return false; }

      Encrypt_then_MAC() = default;

      Encrypt_then_MAC(TLS_Data_Reader& reader, uint16_t extension_size);
   };

/**
* Certificate Status Request (RFC 6066)
*/
class BOTAN_UNSTABLE_API Certificate_Status_Request final : public Extension
   {
   public:
      static Handshake_Extension_Type static_type()
         { return TLSEXT_CERT_STATUS_REQUEST; }

      Handshake_Extension_Type type() const override { return static_type(); }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return false; }

      const std::vector<uint8_t>& get_responder_id_list() const
         {
         return m_ocsp_names;
         }

      const std::vector<uint8_t>& get_request_extensions() const
         {
         return m_extension_bytes;
         }

      const std::vector<uint8_t>& get_ocsp_response() const
         {
         return m_response;
         }

      // Server generated version: empty
      Certificate_Status_Request() {}

      // Client version, both lists can be empty
      Certificate_Status_Request(const std::vector<uint8_t>& ocsp_responder_ids,
                                 const std::vector<std::vector<uint8_t>>& ocsp_key_ids);

      Certificate_Status_Request(TLS_Data_Reader& reader,
                                 uint16_t extension_size,
                                 Connection_Side side,
                                 Handshake_Type message_type);
   private:
      std::vector<uint8_t> m_ocsp_names;
      std::vector<std::vector<uint8_t>> m_ocsp_keys; // is this field really needed
      std::vector<uint8_t> m_extension_bytes;
      std::vector<uint8_t> m_response;
   };

/**
* Supported Versions from RFC 8446
*/
class BOTAN_UNSTABLE_API Supported_Versions final : public Extension
   {
   public:
      static Handshake_Extension_Type static_type()
         { return TLSEXT_SUPPORTED_VERSIONS; }

      Handshake_Extension_Type type() const override { return static_type(); }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return m_versions.empty(); }

      Supported_Versions(Protocol_Version version, const Policy& policy);

      Supported_Versions(Protocol_Version version)
         {
         m_versions.push_back(version);
         }

      Supported_Versions(TLS_Data_Reader& reader,
                         uint16_t extension_size,
                         Connection_Side from);

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
class BOTAN_UNSTABLE_API Record_Size_Limit final : public Extension
   {
   public:
      static Handshake_Extension_Type static_type()
         { return TLSEXT_RECORD_SIZE_LIMIT; }

      Handshake_Extension_Type type() const override { return static_type(); }

      explicit Record_Size_Limit(const uint16_t limit);

      Record_Size_Limit(TLS_Data_Reader& reader, uint16_t extension_size, Connection_Side from);

      uint16_t limit() const { return m_limit; }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return m_limit == 0; }

   private:
      uint16_t m_limit;
   };

using Named_Group = Group_Params;

#if defined(BOTAN_HAS_TLS_13)
/**
* Cookie from RFC 8446 4.2.2
*/
class BOTAN_UNSTABLE_API Cookie final : public Extension
   {
   public:
      static Handshake_Extension_Type static_type()
         { return TLSEXT_COOKIE; }

      Handshake_Extension_Type type() const override { return static_type(); }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return m_cookie.empty(); }

      const std::vector<uint8_t>& get_cookie() const { return m_cookie; }

      explicit Cookie(const std::vector<uint8_t>& cookie);

      explicit Cookie(TLS_Data_Reader& reader,
                      uint16_t extension_size);

   private:
      std::vector<uint8_t> m_cookie;
   };

/**
* Pre-Shared Key Exchange Modes from RFC 8446 4.2.9
*/
class BOTAN_UNSTABLE_API PSK_Key_Exchange_Modes final : public Extension
   {
   public:
      static Handshake_Extension_Type static_type()
         { return TLSEXT_PSK_KEY_EXCHANGE_MODES; }

      Handshake_Extension_Type type() const override { return static_type(); }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return m_modes.empty(); }

      const std::vector<PSK_Key_Exchange_Mode>& modes() const { return m_modes; }

      explicit PSK_Key_Exchange_Modes(std::vector<PSK_Key_Exchange_Mode> modes)
         : m_modes(std::move(modes)) {}

      explicit PSK_Key_Exchange_Modes(TLS_Data_Reader& reader, uint16_t extension_size);

   private:
      std::vector<PSK_Key_Exchange_Mode> m_modes;
   };


/**
 * Certificate Authorities Extension from RFC 8446 4.2.4
 */
class BOTAN_UNSTABLE_API Certificate_Authorities final : public Extension
   {
   public:
      static Handshake_Extension_Type static_type()
         { return TLSEXT_CERTIFICATE_AUTHORITIES; }

      Handshake_Extension_Type type() const override { return static_type(); }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return m_distinguished_names.empty(); }

      const std::vector<X509_DN>& distinguished_names() const
         { return m_distinguished_names; }

      explicit Certificate_Authorities(TLS_Data_Reader& reader, uint16_t extension_size);

   private:
      std::vector<X509_DN> m_distinguished_names;
   };

/**
* Signature_Algorithms_Cert from RFC 8446
*/
class BOTAN_UNSTABLE_API Signature_Algorithms_Cert final : public Extension
   {
   public:
      static Handshake_Extension_Type static_type()
         { return TLSEXT_SIGNATURE_ALGORITHMS_CERT; }

      Handshake_Extension_Type type() const override { return static_type(); }

      const std::vector<Signature_Scheme>& supported_schemes() const { return m_siganture_algorithms.supported_schemes(); }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return m_siganture_algorithms.empty(); }

      explicit Signature_Algorithms_Cert(const std::vector<Signature_Scheme>& schemes);

      Signature_Algorithms_Cert(TLS_Data_Reader& reader, uint16_t extension_size);

   private:
      const Signature_Algorithms m_siganture_algorithms;
   };

/**
* Key_Share from RFC 8446 4.2.8
*/
class BOTAN_UNSTABLE_API Key_Share final : public Extension
   {
   public:
      static Handshake_Extension_Type static_type()
         { return TLSEXT_KEY_SHARE; }

      Handshake_Extension_Type type() const override { return static_type(); }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override;

      /**
       * Perform key exchange with the peer's key share.
       * This method can be called on a ClientHello's Key_Share with a ServerHello's Key_Share or vice versa.
       */
      secure_vector<uint8_t> exchange(const Key_Share& peer_keyshare, const Policy& policy, Callbacks& cb, RandomNumberGenerator& rng) const;

      /**
       * Update a ClientHello's Key_Share to comply with a HelloRetryRequest.
       *
       * This will create new Key_Share_Entries and should only be called on a ClientHello Key_Share with a HelloRetryRequest Key_Share.
       */
      void retry_offer(const Key_Share& retry_request_keyshare, const std::vector<Named_Group>& supported_groups, Callbacks& cb, RandomNumberGenerator& rng);

      /**
       * Delete all private keys that might be contained in Key_Share_Entries in this extension.
       */
      void erase();

      explicit Key_Share(TLS_Data_Reader& reader,
                         uint16_t extension_size,
                         Handshake_Type message_type);

      // constuctor used for ClientHello msg
      explicit Key_Share(const Policy& policy, Callbacks& cb, RandomNumberGenerator& rng);

      // destructor implemented in .cpp to hide Key_Share_Impl
      ~Key_Share();

   private:
      class Key_Share_Impl;
      std::unique_ptr<Key_Share_Impl> m_impl;
   };
#endif

/**
* Unknown extensions are deserialized as this type
*/
class BOTAN_UNSTABLE_API Unknown_Extension final : public Extension
   {
   public:
      Unknown_Extension(Handshake_Extension_Type type,
                        TLS_Data_Reader& reader,
                        uint16_t extension_size);

      std::vector<uint8_t> serialize(Connection_Side whoami) const override; // always fails

      const std::vector<uint8_t>& value() { return m_value; }

      bool empty() const override { return false; }

      Handshake_Extension_Type type() const override { return m_type; }

      bool is_implemented() const override { return false; }

   private:
      Handshake_Extension_Type m_type;
      std::vector<uint8_t> m_value;
   };

/**
* Represents a block of extensions in a hello message
*/
class BOTAN_UNSTABLE_API Extensions final
   {
   public:
      std::set<Handshake_Extension_Type> extension_types() const;

      template<typename T>
      T* get() const
         {
         return dynamic_cast<T*>(get(T::static_type()));
         }

      template<typename T>
      bool has() const
         {
         return get<T>() != nullptr;
         }

      bool has(Handshake_Extension_Type type) const
         {
         return get(type) != nullptr;
         }

      size_t size() const
         {
         return m_extensions.size();
         }

      void add(std::unique_ptr<Extension> extn);

      void add(Extension* extn)
         {
         add(std::unique_ptr<Extension>(extn));
         }

      Extension* get(Handshake_Extension_Type type) const
         {
         const auto i = std::find_if(m_extensions.cbegin(), m_extensions.cend(),
                                     [type](const auto &ext) {
                                        return ext->type() == type;
                                     });

         return (i != m_extensions.end()) ? i->get() : nullptr;
         }

      std::vector<uint8_t> serialize(Connection_Side whoami) const;

      void deserialize(TLS_Data_Reader& reader,
                       const Connection_Side from,
                       const Handshake_Type message_type);

      /**
       * @param allowed_extensions        extension types that are allowed
       * @param allow_unknown_extensions  if true, ignores unrecognized extensions
       * @returns true if this contains any extensions that are not contained in @p allowed_extensions.
       */
      bool contains_other_than(const std::set<Handshake_Extension_Type>& allowed_extensions,
                               const bool allow_unknown_extensions = false) const;

      /**
       * @param allowed_extensions  extension types that are allowed
       * @returns true if this contains any extensions implemented by Botan that
       *          are not contained in @p allowed_extensions.
       */
      bool contains_implemented_extensions_other_than(const std::set<Handshake_Extension_Type>& allowed_extensions) const
         {
         return contains_other_than(allowed_extensions, true);
         }

      /**
       * Take the extension with the given type out of the extensions list.
       * Returns a nullptr if the extension didn't exist.
       */
      template<typename T>
      decltype(auto) take()
         {
         std::unique_ptr<T> out_ptr;

         auto ext = take(T::static_type());
         if (ext != nullptr) {
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
      std::unique_ptr<Extension> take(Handshake_Extension_Type type);

      /**
      * Remove an extension from this extensions object, if it exists.
      * Returns true if the extension existed (and thus is now removed),
      * otherwise false (the extension wasn't set in the first place).
      *
      * Note: not used internally, might be used in Callbacks::tls_modify_extensions()
      */
      bool remove_extension(Handshake_Extension_Type type)
         {
         return take(type) != nullptr;
         }

      Extensions() = default;
      Extensions(Extensions&&) = default;
      Extensions& operator=(Extensions&&) = default;

      Extensions(TLS_Data_Reader& reader, Connection_Side side, Handshake_Type message_type)
         {
         deserialize(reader, side, message_type);
         }

   private:
      Extensions(const Extensions&) = delete;
      Extensions& operator=(const Extensions&) = delete;

      std::vector<std::unique_ptr<Extension>> m_extensions;
   };

}

}

#endif
