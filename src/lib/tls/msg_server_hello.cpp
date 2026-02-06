/*
* TLS Server Hello and Server Hello Done
* (C) 2004-2011,2015,2016,2019 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*     2021 Elektrobit Automotive GmbH
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*     2026 René Meusel - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>
#include <botan/internal/tls_messages_internal.h>

#include <botan/tls_alert.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/tls_reader.h>

namespace Botan::TLS {

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
      const auto lastbytes = std::span{random}.last(downgrade_signal_length);
      store_be(DOWNGRADE_TLS12, lastbytes);
   }

   return random;
}

Server_Hello_Internal::Server_Hello_Internal(const std::vector<uint8_t>& buf) {
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
   m_is_hello_retry_request = CT::is_equal<uint8_t>(m_random, HELLO_RETRY_REQUEST_MARKER).as_bool();

   m_session_id = Session_ID(reader.get_range<uint8_t>(1, 0, 32));
   m_ciphersuite = reader.get_uint16_t();
   m_comp_method = reader.get_byte();

   // Note that this code path might parse a TLS 1.2 (or older) server hello message that
   // is nevertheless marked as being a 'hello retry request' (potentially maliciously).
   // Extension parsing will however not be affected by the associated flag.
   // Only after parsing the extensions will the upstream code be able to decide
   // whether we're dealing with TLS 1.3 or older.
   m_extensions.deserialize(reader,
                            Connection_Side::Server,
                            m_is_hello_retry_request ? Handshake_Type::HelloRetryRequest : Handshake_Type::ServerHello);
}

Protocol_Version Server_Hello_Internal::version() const {
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

Server_Hello_12_Shim::Server_Hello_12_Shim(const std::vector<uint8_t>& buf) :
      Server_Hello_12_Shim(std::make_unique<Server_Hello_Internal>(buf)) {}

Server_Hello_12_Shim::Server_Hello_12_Shim(std::unique_ptr<Server_Hello_Internal> data) :
      Server_Hello(std::move(data)) {
   if(!m_data->version().is_pre_tls_13()) {
      throw TLS_Exception(Alert::ProtocolVersion, "Expected server hello of (D)TLS 1.2 or lower");
   }
}

Protocol_Version Server_Hello_12_Shim::selected_version() const {
   return legacy_version();
}

std::optional<Protocol_Version> Server_Hello_12_Shim::random_signals_downgrade() const {
   const uint64_t last8 = load_be<uint64_t>(m_data->random().data(), 3);
   if(last8 == DOWNGRADE_TLS11) {
      return Protocol_Version::TLS_V11;
   }
   if(last8 == DOWNGRADE_TLS12) {
      return Protocol_Version::TLS_V12;
   }

   return std::nullopt;
}

}  // namespace Botan::TLS
