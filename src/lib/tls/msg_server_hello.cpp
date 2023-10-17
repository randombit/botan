/*
* TLS Server Hello and Server Hello Done
* (C) 2004-2011,2015,2016,2019 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*     2021 Elektrobit Automotive GmbH
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>

#include <botan/mem_ops.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_extensions.h>
#include <botan/tls_session_manager.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_session_key.h>

#include <array>

namespace Botan::TLS {

namespace {

const uint64_t DOWNGRADE_TLS11 = 0x444F574E47524400;
const uint64_t DOWNGRADE_TLS12 = 0x444F574E47524401;

// SHA-256("HelloRetryRequest")
const std::vector<uint8_t> HELLO_RETRY_REQUEST_MARKER = {
   0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
   0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C};

bool random_signals_hello_retry_request(const std::vector<uint8_t>& random) {
   return CT::is_equal(random.data(), HELLO_RETRY_REQUEST_MARKER.data(), HELLO_RETRY_REQUEST_MARKER.size()).as_bool();
}

std::vector<uint8_t> make_server_hello_random(RandomNumberGenerator& rng,
                                              Protocol_Version offered_version,
                                              Callbacks& cb,
                                              const Policy& policy) {
   BOTAN_UNUSED(offered_version);
   auto random = make_hello_random(rng, cb, policy);

   // RFC 8446 4.1.3
   //    TLS 1.3 has a downgrade protection mechanism embedded in the server's
   //    random value. TLS 1.3 servers which negotiate TLS 1.2 or below in
   //    response to a ClientHello MUST set the last 8 bytes of their Random
   //    value specially in their ServerHello.
   //
   //    If negotiating TLS 1.2, TLS 1.3 servers MUST set the last 8 bytes of
   //    their Random value to the bytes: [DOWNGRADE_TLS12]
   if(offered_version.is_pre_tls_13() && policy.allow_tls13()) {
      constexpr size_t downgrade_signal_length = sizeof(DOWNGRADE_TLS12);
      BOTAN_ASSERT_NOMSG(random.size() >= downgrade_signal_length);
      auto lastbytes = random.data() + random.size() - downgrade_signal_length;
      store_be(DOWNGRADE_TLS12, lastbytes);
   }

   return random;
}

}  // namespace

/**
* Version-agnostic internal server hello data container that allows
* parsing Server_Hello messages without prior knowledge of the contained
* protocol version.
*/
class Server_Hello_Internal {
   public:
      /**
       * Deserialize a Server Hello message
       */
      Server_Hello_Internal(const std::vector<uint8_t>& buf) {
         if(buf.size() < 38) {
            throw Decoding_Error("Server_Hello: Packet corrupted");
         }

         TLS_Data_Reader reader("ServerHello", buf);

         const uint8_t major_version = reader.get_byte();
         const uint8_t minor_version = reader.get_byte();

         m_legacy_version = Protocol_Version(major_version, minor_version);

         // RFC 8446 4.1.3
         //    Upon receiving a message with type server_hello, implementations MUST
         //    first examine the Random value and, if it matches this value, process
         //    it as described in Section 4.1.4 [Hello Retry Request]).
         m_random = reader.get_fixed<uint8_t>(32);
         m_is_hello_retry_request = random_signals_hello_retry_request(m_random);

         m_session_id = Session_ID(reader.get_range<uint8_t>(1, 0, 32));
         m_ciphersuite = reader.get_uint16_t();
         m_comp_method = reader.get_byte();

         // Note that this code path might parse a TLS 1.2 (or older) server hello message that
         // is nevertheless marked as being a 'hello retry request' (potentially maliciously).
         // Extension parsing will however not be affected by the associated flag.
         // Only after parsing the extensions will the upstream code be able to decide
         // whether we're dealing with TLS 1.3 or older.
         m_extensions.deserialize(
            reader,
            Connection_Side::Server,
            m_is_hello_retry_request ? Handshake_Type::HelloRetryRequest : Handshake_Type::ServerHello);
      }

      Server_Hello_Internal(Protocol_Version lv,
                            Session_ID sid,
                            std::vector<uint8_t> r,
                            const uint16_t cs,
                            const uint8_t cm,
                            bool is_hrr = false) :
            m_legacy_version(lv),
            m_session_id(std::move(sid)),
            m_random(std::move(r)),
            m_is_hello_retry_request(is_hrr),
            m_ciphersuite(cs),
            m_comp_method(cm) {}

      Protocol_Version version() const {
         // RFC 8446 4.2.1
         //    A server which negotiates a version of TLS prior to TLS 1.3 MUST set
         //    ServerHello.version and MUST NOT send the "supported_versions"
         //    extension.  A server which negotiates TLS 1.3 MUST respond by sending
         //    a "supported_versions" extension containing the selected version
         //    value (0x0304).
         //
         // Note: Here we just take a message parsing decision, further validation of
         //       the extension's contents is done later.
         return (extensions().has<Supported_Versions>()) ? Protocol_Version::TLS_V13 : m_legacy_version;
      }

      Protocol_Version legacy_version() const { return m_legacy_version; }

      const Session_ID& session_id() const { return m_session_id; }

      const std::vector<uint8_t>& random() const { return m_random; }

      uint16_t ciphersuite() const { return m_ciphersuite; }

      uint8_t comp_method() const { return m_comp_method; }

      bool is_hello_retry_request() const { return m_is_hello_retry_request; }

      const Extensions& extensions() const { return m_extensions; }

      Extensions& extensions() { return m_extensions; }

   private:
      Protocol_Version m_legacy_version;
      Session_ID m_session_id;
      std::vector<uint8_t> m_random;
      bool m_is_hello_retry_request;
      uint16_t m_ciphersuite;
      uint8_t m_comp_method;

      Extensions m_extensions;
};

Server_Hello::Server_Hello(std::unique_ptr<Server_Hello_Internal> data) : m_data(std::move(data)) {}

Server_Hello::Server_Hello(Server_Hello&&) noexcept = default;
Server_Hello& Server_Hello::operator=(Server_Hello&&) noexcept = default;

Server_Hello::~Server_Hello() = default;

/*
* Serialize a Server Hello message
*/
std::vector<uint8_t> Server_Hello::serialize() const {
   std::vector<uint8_t> buf;
   buf.reserve(1024);  // working around GCC warning

   buf.push_back(m_data->legacy_version().major_version());
   buf.push_back(m_data->legacy_version().minor_version());
   buf += m_data->random();

   append_tls_length_value(buf, m_data->session_id().get(), 1);

   buf.push_back(get_byte<0>(m_data->ciphersuite()));
   buf.push_back(get_byte<1>(m_data->ciphersuite()));

   buf.push_back(m_data->comp_method());

   buf += m_data->extensions().serialize(Connection_Side::Server);

   return buf;
}

Handshake_Type Server_Hello::type() const {
   return Handshake_Type::ServerHello;
}

Protocol_Version Server_Hello::legacy_version() const {
   return m_data->legacy_version();
}

const std::vector<uint8_t>& Server_Hello::random() const {
   return m_data->random();
}

uint8_t Server_Hello::compression_method() const {
   return m_data->comp_method();
}

const Session_ID& Server_Hello::session_id() const {
   return m_data->session_id();
}

uint16_t Server_Hello::ciphersuite() const {
   return m_data->ciphersuite();
}

std::set<Extension_Code> Server_Hello::extension_types() const {
   return m_data->extensions().extension_types();
}

const Extensions& Server_Hello::extensions() const {
   return m_data->extensions();
}

// New session case
Server_Hello_12::Server_Hello_12(Handshake_IO& io,
                                 Handshake_Hash& hash,
                                 const Policy& policy,
                                 Callbacks& cb,
                                 RandomNumberGenerator& rng,
                                 const std::vector<uint8_t>& reneg_info,
                                 const Client_Hello_12& client_hello,
                                 const Server_Hello_12::Settings& server_settings,
                                 std::string_view next_protocol) :
      Server_Hello(std::make_unique<Server_Hello_Internal>(
         server_settings.protocol_version(),
         server_settings.session_id(),
         make_server_hello_random(rng, server_settings.protocol_version(), cb, policy),
         server_settings.ciphersuite(),
         uint8_t(0))) {
   if(client_hello.supports_extended_master_secret()) {
      m_data->extensions().add(new Extended_Master_Secret);
   }

   // Sending the extension back does not commit us to sending a stapled response
   if(client_hello.supports_cert_status_message() && policy.support_cert_status_message()) {
      m_data->extensions().add(new Certificate_Status_Request);
   }

   if(!next_protocol.empty() && client_hello.supports_alpn()) {
      m_data->extensions().add(new Application_Layer_Protocol_Notification(next_protocol));
   }

   const auto c = Ciphersuite::by_id(m_data->ciphersuite());

   if(c && c->cbc_ciphersuite() && client_hello.supports_encrypt_then_mac() && policy.negotiate_encrypt_then_mac()) {
      m_data->extensions().add(new Encrypt_then_MAC);
   }

   if(c && c->ecc_ciphersuite() && client_hello.extension_types().contains(Extension_Code::EcPointFormats)) {
      m_data->extensions().add(new Supported_Point_Formats(policy.use_ecc_point_compression()));
   }

   if(client_hello.secure_renegotiation()) {
      m_data->extensions().add(new Renegotiation_Extension(reneg_info));
   }

   if(client_hello.supports_session_ticket() && server_settings.offer_session_ticket()) {
      m_data->extensions().add(new Session_Ticket_Extension());
   }

   if(m_data->legacy_version().is_datagram_protocol()) {
      const std::vector<uint16_t> server_srtp = policy.srtp_profiles();
      const std::vector<uint16_t> client_srtp = client_hello.srtp_profiles();

      if(!server_srtp.empty() && !client_srtp.empty()) {
         uint16_t shared = 0;
         // always using server preferences for now
         for(auto s_srtp : server_srtp) {
            for(auto c_srtp : client_srtp) {
               if(shared == 0 && s_srtp == c_srtp) {
                  shared = s_srtp;
               }
            }
         }

         if(shared) {
            m_data->extensions().add(new SRTP_Protection_Profiles(shared));
         }
      }
   }

   cb.tls_modify_extensions(m_data->extensions(), Connection_Side::Server, type());

   hash.update(io.send(*this));
}

// Resuming
Server_Hello_12::Server_Hello_12(Handshake_IO& io,
                                 Handshake_Hash& hash,
                                 const Policy& policy,
                                 Callbacks& cb,
                                 RandomNumberGenerator& rng,
                                 const std::vector<uint8_t>& reneg_info,
                                 const Client_Hello_12& client_hello,
                                 const Session& resumed_session,
                                 bool offer_session_ticket,
                                 std::string_view next_protocol) :
      Server_Hello(std::make_unique<Server_Hello_Internal>(resumed_session.version(),
                                                           client_hello.session_id(),
                                                           make_hello_random(rng, cb, policy),
                                                           resumed_session.ciphersuite_code(),
                                                           uint8_t(0))) {
   if(client_hello.supports_extended_master_secret()) {
      m_data->extensions().add(new Extended_Master_Secret);
   }

   if(!next_protocol.empty() && client_hello.supports_alpn()) {
      m_data->extensions().add(new Application_Layer_Protocol_Notification(next_protocol));
   }

   if(client_hello.supports_encrypt_then_mac() && policy.negotiate_encrypt_then_mac()) {
      Ciphersuite c = resumed_session.ciphersuite();
      if(c.cbc_ciphersuite()) {
         m_data->extensions().add(new Encrypt_then_MAC);
      }
   }

   if(resumed_session.ciphersuite().ecc_ciphersuite() &&
      client_hello.extension_types().contains(Extension_Code::EcPointFormats)) {
      m_data->extensions().add(new Supported_Point_Formats(policy.use_ecc_point_compression()));
   }

   if(client_hello.secure_renegotiation()) {
      m_data->extensions().add(new Renegotiation_Extension(reneg_info));
   }

   if(client_hello.supports_session_ticket() && offer_session_ticket) {
      m_data->extensions().add(new Session_Ticket_Extension());
   }

   cb.tls_modify_extensions(m_data->extensions(), Connection_Side::Server, type());

   hash.update(io.send(*this));
}

Server_Hello_12::Server_Hello_12(const std::vector<uint8_t>& buf) :
      Server_Hello_12(std::make_unique<Server_Hello_Internal>(buf)) {}

Server_Hello_12::Server_Hello_12(std::unique_ptr<Server_Hello_Internal> data) : Server_Hello(std::move(data)) {
   if(!m_data->version().is_pre_tls_13()) {
      throw TLS_Exception(Alert::ProtocolVersion, "Expected server hello of (D)TLS 1.2 or lower");
   }
}

Protocol_Version Server_Hello_12::selected_version() const {
   return legacy_version();
}

bool Server_Hello_12::secure_renegotiation() const {
   return m_data->extensions().has<Renegotiation_Extension>();
}

std::vector<uint8_t> Server_Hello_12::renegotiation_info() const {
   if(Renegotiation_Extension* reneg = m_data->extensions().get<Renegotiation_Extension>()) {
      return reneg->renegotiation_info();
   }
   return std::vector<uint8_t>();
}

bool Server_Hello_12::supports_extended_master_secret() const {
   return m_data->extensions().has<Extended_Master_Secret>();
}

bool Server_Hello_12::supports_encrypt_then_mac() const {
   return m_data->extensions().has<Encrypt_then_MAC>();
}

bool Server_Hello_12::supports_certificate_status_message() const {
   return m_data->extensions().has<Certificate_Status_Request>();
}

bool Server_Hello_12::supports_session_ticket() const {
   return m_data->extensions().has<Session_Ticket_Extension>();
}

uint16_t Server_Hello_12::srtp_profile() const {
   if(auto srtp = m_data->extensions().get<SRTP_Protection_Profiles>()) {
      auto prof = srtp->profiles();
      if(prof.size() != 1 || prof[0] == 0) {
         throw Decoding_Error("Server sent malformed DTLS-SRTP extension");
      }
      return prof[0];
   }

   return 0;
}

std::string Server_Hello_12::next_protocol() const {
   if(auto alpn = m_data->extensions().get<Application_Layer_Protocol_Notification>()) {
      return alpn->single_protocol();
   }
   return "";
}

bool Server_Hello_12::prefers_compressed_ec_points() const {
   if(auto ecc_formats = m_data->extensions().get<Supported_Point_Formats>()) {
      return ecc_formats->prefers_compressed();
   }
   return false;
}

std::optional<Protocol_Version> Server_Hello_12::random_signals_downgrade() const {
   const uint64_t last8 = load_be<uint64_t>(m_data->random().data(), 3);
   if(last8 == DOWNGRADE_TLS11) {
      return Protocol_Version::TLS_V11;
   }
   if(last8 == DOWNGRADE_TLS12) {
      return Protocol_Version::TLS_V12;
   }

   return std::nullopt;
}

/*
* Create a new Server Hello Done message
*/
Server_Hello_Done::Server_Hello_Done(Handshake_IO& io, Handshake_Hash& hash) {
   hash.update(io.send(*this));
}

/*
* Deserialize a Server Hello Done message
*/
Server_Hello_Done::Server_Hello_Done(const std::vector<uint8_t>& buf) {
   if(!buf.empty()) {
      throw Decoding_Error("Server_Hello_Done: Must be empty, and is not");
   }
}

/*
* Serialize a Server Hello Done message
*/
std::vector<uint8_t> Server_Hello_Done::serialize() const {
   return std::vector<uint8_t>();
}

#if defined(BOTAN_HAS_TLS_13)

const Server_Hello_13::Server_Hello_Tag Server_Hello_13::as_server_hello;
const Server_Hello_13::Hello_Retry_Request_Tag Server_Hello_13::as_hello_retry_request;
const Server_Hello_13::Hello_Retry_Request_Creation_Tag Server_Hello_13::as_new_hello_retry_request;

std::variant<Hello_Retry_Request, Server_Hello_13> Server_Hello_13::create(const Client_Hello_13& ch,
                                                                           bool hello_retry_request_allowed,
                                                                           Session_Manager& session_mgr,
                                                                           Credentials_Manager& credentials_mgr,
                                                                           RandomNumberGenerator& rng,
                                                                           const Policy& policy,
                                                                           Callbacks& cb) {
   const auto& exts = ch.extensions();

   // RFC 8446 4.2.9
   //    [With PSK with (EC)DHE key establishment], the client and server MUST
   //    supply "key_share" values [...].
   //
   // Note: We currently do not support PSK without (EC)DHE, hence, we can
   //       assume that those extensions are available.
   BOTAN_ASSERT_NOMSG(exts.has<Supported_Groups>() && exts.has<Key_Share>());
   const auto& supported_by_client = exts.get<Supported_Groups>()->groups();
   const auto& offered_by_client = exts.get<Key_Share>()->offered_groups();
   const auto selected_group = policy.choose_key_exchange_group(supported_by_client, offered_by_client);

   // RFC 8446 4.1.1
   //    If there is no overlap between the received "supported_groups" and the
   //    groups supported by the server, then the server MUST abort the
   //    handshake with a "handshake_failure" or an "insufficient_security" alert.
   if(selected_group == Named_Group::NONE) {
      throw TLS_Exception(Alert::HandshakeFailure, "Client did not offer any acceptable group");
   }

   // RFC 8446 4.2.8:
   //    Servers MUST NOT send a KeyShareEntry for any group not indicated in the
   //    client's "supported_groups" extension [...]
   if(!value_exists(supported_by_client, selected_group)) {
      throw TLS_Exception(Alert::InternalError, "Application selected a group that is not supported by the client");
   }

   // RFC 8446 4.1.4
   //    The server will send this message in response to a ClientHello
   //    message if it is able to find an acceptable set of parameters but the
   //    ClientHello does not contain sufficient information to proceed with
   //    the handshake.
   //
   // In this case, the Client Hello did not contain a key share offer for
   // the group selected by the application.
   if(!value_exists(offered_by_client, selected_group)) {
      // RFC 8446 4.1.4
      //    If a client receives a second HelloRetryRequest in the same
      //    connection (i.e., where the ClientHello was itself in response to a
      //    HelloRetryRequest), it MUST abort the handshake with an
      //    "unexpected_message" alert.
      BOTAN_STATE_CHECK(hello_retry_request_allowed);
      return Hello_Retry_Request(ch, selected_group, policy, cb);
   } else {
      return Server_Hello_13(ch, selected_group, session_mgr, credentials_mgr, rng, cb, policy);
   }
}

std::variant<Hello_Retry_Request, Server_Hello_13, Server_Hello_12> Server_Hello_13::parse(
   const std::vector<uint8_t>& buf) {
   auto data = std::make_unique<Server_Hello_Internal>(buf);
   const auto version = data->version();

   // server hello that appears to be pre-TLS 1.3, takes precedence over...
   if(version.is_pre_tls_13()) {
      return Server_Hello_12(std::move(data));
   }

   // ... the TLS 1.3 "special case" aka. Hello_Retry_Request
   if(version == Protocol_Version::TLS_V13) {
      if(data->is_hello_retry_request()) {
         return Hello_Retry_Request(std::move(data));
      }

      return Server_Hello_13(std::move(data));
   }

   throw TLS_Exception(Alert::ProtocolVersion, "unexpected server hello version: " + version.to_string());
}

/**
 * Validation that applies to both Server Hello and Hello Retry Request
 */
void Server_Hello_13::basic_validation() const {
   BOTAN_ASSERT_NOMSG(m_data->version() == Protocol_Version::TLS_V13);

   // Note: checks that cannot be performed without contextual information
   //       are done in the specific TLS client implementation.
   // Note: The Supported_Version extension makes sure internally that
   //       exactly one entry is provided.

   // Note: Hello Retry Request basic validation is equivalent with the
   //       basic validations required for Server Hello
   //
   // RFC 8446 4.1.4
   //    Upon receipt of a HelloRetryRequest, the client MUST check the
   //    legacy_version, [...], and legacy_compression_method as specified in
   //    Section 4.1.3 and then process the extensions, starting with determining
   //    the version using "supported_versions".

   // RFC 8446 4.1.3
   //    In TLS 1.3, [...] the legacy_version field MUST be set to 0x0303
   if(legacy_version() != Protocol_Version::TLS_V12) {
      throw TLS_Exception(Alert::ProtocolVersion,
                          "legacy_version '" + legacy_version().to_string() + "' is not allowed");
   }

   // RFC 8446 4.1.3
   //    legacy_compression_method:  A single byte which MUST have the value 0.
   if(compression_method() != 0x00) {
      throw TLS_Exception(Alert::DecodeError, "compression is not supported in TLS 1.3");
   }

   // RFC 8446 4.1.3
   //    All TLS 1.3 ServerHello messages MUST contain the "supported_versions" extension.
   if(!extensions().has<Supported_Versions>()) {
      throw TLS_Exception(Alert::MissingExtension, "server hello did not contain 'supported version' extension");
   }

   // RFC 8446 4.2.1
   //    A server which negotiates TLS 1.3 MUST respond by sending
   //    a "supported_versions" extension containing the selected version
   //    value (0x0304).
   if(selected_version() != Protocol_Version::TLS_V13) {
      throw TLS_Exception(Alert::IllegalParameter, "TLS 1.3 Server Hello selected a different version");
   }
}

Server_Hello_13::Server_Hello_13(std::unique_ptr<Server_Hello_Internal> data, Server_Hello_13::Server_Hello_Tag) :
      Server_Hello(std::move(data)) {
   BOTAN_ASSERT_NOMSG(!m_data->is_hello_retry_request());
   basic_validation();

   const auto& exts = extensions();

   // RFC 8446 4.1.3
   //    The ServerHello MUST only include extensions which are required to
   //    establish the cryptographic context and negotiate the protocol version.
   //    [...]
   //    Other extensions (see Section 4.2) are sent separately in the
   //    EncryptedExtensions message.
   //
   // Note that further validation dependent on the client hello is done in the
   // TLS client implementation.
   const std::set<Extension_Code> allowed = {
      Extension_Code::KeyShare,
      Extension_Code::SupportedVersions,
      Extension_Code::PresharedKey,
   };

   // As the ServerHello shall only contain essential extensions, we don't give
   // any slack for extensions not implemented by Botan here.
   if(exts.contains_other_than(allowed)) {
      throw TLS_Exception(Alert::UnsupportedExtension, "Server Hello contained an extension that is not allowed");
   }

   // RFC 8446 4.1.3
   //    Current ServerHello messages additionally contain
   //    either the "pre_shared_key" extension or the "key_share"
   //    extension, or both [...].
   if(!exts.has<Key_Share>() && !exts.has<PSK_Key_Exchange_Modes>()) {
      throw TLS_Exception(Alert::MissingExtension, "server hello must contain key exchange information");
   }
}

Server_Hello_13::Server_Hello_13(std::unique_ptr<Server_Hello_Internal> data,
                                 Server_Hello_13::Hello_Retry_Request_Tag) :
      Server_Hello(std::move(data)) {
   BOTAN_ASSERT_NOMSG(m_data->is_hello_retry_request());
   basic_validation();

   const auto& exts = extensions();

   // RFC 8446 4.1.4
   //     The HelloRetryRequest extensions defined in this specification are:
   //     -  supported_versions (see Section 4.2.1)
   //     -  cookie (see Section 4.2.2)
   //     -  key_share (see Section 4.2.8)
   const std::set<Extension_Code> allowed = {
      Extension_Code::Cookie,
      Extension_Code::SupportedVersions,
      Extension_Code::KeyShare,
   };

   // As the Hello Retry Request shall only contain essential extensions, we
   // don't give any slack for extensions not implemented by Botan here.
   if(exts.contains_other_than(allowed)) {
      throw TLS_Exception(Alert::UnsupportedExtension,
                          "Hello Retry Request contained an extension that is not allowed");
   }

   // RFC 8446 4.1.4
   //    Clients MUST abort the handshake with an "illegal_parameter" alert if
   //    the HelloRetryRequest would not result in any change in the ClientHello.
   if(!exts.has<Key_Share>() && !exts.has<Cookie>()) {
      throw TLS_Exception(Alert::IllegalParameter, "Hello Retry Request does not request any changes to Client Hello");
   }
}

Server_Hello_13::Server_Hello_13(std::unique_ptr<Server_Hello_Internal> data, Hello_Retry_Request_Creation_Tag) :
      Server_Hello(std::move(data)) {}

namespace {

uint16_t choose_ciphersuite(const Client_Hello_13& ch, const Policy& policy) {
   auto pref_list = ch.ciphersuites();
   // TODO: DTLS might need to make this version dynamic
   auto other_list = policy.ciphersuite_list(Protocol_Version::TLS_V13);

   if(policy.server_uses_own_ciphersuite_preferences()) {
      std::swap(pref_list, other_list);
   }

   for(auto suite_id : pref_list) {
      // TODO: take potentially available PSKs into account to select a
      //       compatible ciphersuite.
      //
      // Assuming the client sent one or more PSKs, we would first need to find
      // the hash functions they are associated to. For session tickets, that
      // would mean decrypting the ticket and comparing the cipher suite used in
      // those tickets. For (currently not yet supported) pre-assigned PSKs, the
      // hash function needs to be specified along with them.
      //
      // Then we could refine the ciphersuite selection using the required hash
      // function for the PSK(s) we are wishing to use down the road.
      //
      // For now, we just negotiate the cipher suite blindly and hope for the
      // best. As long as PSKs are used for session resumption only, this has a
      // high chance of success. Previous handshakes with this client have very
      // likely selected the same ciphersuite anyway.
      //
      // See also RFC 8446 4.2.11
      //    When session resumption is the primary use case of PSKs, the most
      //    straightforward way to implement the PSK/cipher suite matching
      //    requirements is to negotiate the cipher suite first [...].
      if(value_exists(other_list, suite_id)) {
         return suite_id;
      }
   }

   // RFC 8446 4.1.1
   //     If the server is unable to negotiate a supported set of parameters
   //     [...], it MUST abort the handshake with either a "handshake_failure"
   //     or "insufficient_security" fatal alert [...].
   throw TLS_Exception(Alert::HandshakeFailure, "Can't agree on a ciphersuite with client");
}
}  // namespace

Server_Hello_13::Server_Hello_13(const Client_Hello_13& ch,
                                 std::optional<Named_Group> key_exchange_group,
                                 Session_Manager& session_mgr,
                                 Credentials_Manager& credentials_mgr,
                                 RandomNumberGenerator& rng,
                                 Callbacks& cb,
                                 const Policy& policy) :
      Server_Hello(std::make_unique<Server_Hello_Internal>(
         Protocol_Version::TLS_V12,
         ch.session_id(),
         make_server_hello_random(rng, Protocol_Version::TLS_V13, cb, policy),
         choose_ciphersuite(ch, policy),
         uint8_t(0) /* compression method */
         )) {
   // RFC 8446 4.2.1
   //    A server which negotiates TLS 1.3 MUST respond by sending a
   //    "supported_versions" extension containing the selected version
   //    value (0x0304). It MUST set the ServerHello.legacy_version field to
   //     0x0303 (TLS 1.2).
   //
   // Note that the legacy version (TLS 1.2) is set in this constructor's
   // initializer list, accordingly.
   m_data->extensions().add(new Supported_Versions(Protocol_Version::TLS_V13));

   if(key_exchange_group.has_value()) {
      BOTAN_ASSERT_NOMSG(ch.extensions().has<Key_Share>());
      m_data->extensions().add(Key_Share::create_as_encapsulation(
         key_exchange_group.value(), *ch.extensions().get<Key_Share>(), policy, cb, rng));
   }

   auto& ch_exts = ch.extensions();

   if(ch_exts.has<PSK>()) {
      const auto cs = Ciphersuite::by_id(m_data->ciphersuite());
      BOTAN_ASSERT_NOMSG(cs);

      // RFC 8446 4.2.9
      //    A client MUST provide a "psk_key_exchange_modes" extension if it
      //    offers a "pre_shared_key" extension.
      //
      // Note: Client_Hello_13 constructor already performed a graceful check.
      const auto psk_modes = ch_exts.get<PSK_Key_Exchange_Modes>();
      BOTAN_ASSERT_NONNULL(psk_modes);

      // TODO: also support PSK_Key_Exchange_Mode::PSK_KE
      //       (PSK-based handshake without an additional ephemeral key exchange)
      if(value_exists(psk_modes->modes(), PSK_Key_Exchange_Mode::PSK_DHE_KE)) {
         if(auto server_psk = ch_exts.get<PSK>()->select_offered_psk(
               ch.sni_hostname(), cs.value(), session_mgr, credentials_mgr, cb, policy)) {
            // RFC 8446 4.2.11
            //    In order to accept PSK key establishment, the server sends a
            //    "pre_shared_key" extension indicating the selected identity.
            m_data->extensions().add(std::move(server_psk));
         }
      }
   }

   cb.tls_modify_extensions(m_data->extensions(), Connection_Side::Server, type());
}

std::optional<Protocol_Version> Server_Hello_13::random_signals_downgrade() const {
   const uint64_t last8 = load_be<uint64_t>(m_data->random().data(), 3);
   if(last8 == DOWNGRADE_TLS11) {
      return Protocol_Version::TLS_V11;
   }
   if(last8 == DOWNGRADE_TLS12) {
      return Protocol_Version::TLS_V12;
   }

   return std::nullopt;
}

Protocol_Version Server_Hello_13::selected_version() const {
   const auto versions_ext = m_data->extensions().get<Supported_Versions>();
   BOTAN_ASSERT_NOMSG(versions_ext);
   const auto& versions = versions_ext->versions();
   BOTAN_ASSERT_NOMSG(versions.size() == 1);
   return versions.front();
}

Hello_Retry_Request::Hello_Retry_Request(std::unique_ptr<Server_Hello_Internal> data) :
      Server_Hello_13(std::move(data), Server_Hello_13::as_hello_retry_request) {}

Hello_Retry_Request::Hello_Retry_Request(const Client_Hello_13& ch,
                                         Named_Group selected_group,
                                         const Policy& policy,
                                         Callbacks& cb) :
      Server_Hello_13(std::make_unique<Server_Hello_Internal>(Protocol_Version::TLS_V12 /* legacy_version */,
                                                              ch.session_id(),
                                                              HELLO_RETRY_REQUEST_MARKER,
                                                              choose_ciphersuite(ch, policy),
                                                              uint8_t(0) /* compression method */,
                                                              true /* is Hello Retry Request */
                                                              ),
                      as_new_hello_retry_request) {
   // RFC 8446 4.1.4
   //     As with the ServerHello, a HelloRetryRequest MUST NOT contain any
   //     extensions that were not first offered by the client in its
   //     ClientHello, with the exception of optionally the "cookie" [...]
   //     extension.
   BOTAN_STATE_CHECK(ch.extensions().has<Supported_Groups>());
   BOTAN_STATE_CHECK(ch.extensions().has<Key_Share>());

   BOTAN_STATE_CHECK(!value_exists(ch.extensions().get<Key_Share>()->offered_groups(), selected_group));

   // RFC 8446 4.1.4
   //    The server's extensions MUST contain "supported_versions".
   //
   // RFC 8446 4.2.1
   //    A server which negotiates TLS 1.3 MUST respond by sending a
   //    "supported_versions" extension containing the selected version
   //    value (0x0304). It MUST set the ServerHello.legacy_version field to
   //    0x0303 (TLS 1.2).
   //
   // Note that the legacy version (TLS 1.2) is set in this constructor's
   // initializer list, accordingly.
   m_data->extensions().add(new Supported_Versions(Protocol_Version::TLS_V13));

   m_data->extensions().add(new Key_Share(selected_group));

   cb.tls_modify_extensions(m_data->extensions(), Connection_Side::Server, type());
}

#endif  // BOTAN_HAS_TLS_13

}  // namespace Botan::TLS
