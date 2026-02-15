/*
* TLS Client Hello Messages
* (C) 2004-2011,2015,2016 Jack Lloyd
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

#include <botan/hash.h>
#include <botan/rng.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_policy.h>
#include <botan/internal/tls_reader.h>

namespace Botan::TLS {

std::vector<uint8_t> make_hello_random(RandomNumberGenerator& rng, Callbacks& cb, const Policy& policy) {
   auto buf = rng.random_vec<std::vector<uint8_t>>(32);

   if(policy.hash_hello_random()) {
      auto sha256 = HashFunction::create_or_throw("SHA-256");
      sha256->update(buf);
      sha256->final(buf);
   }

   // TLS 1.3 does not require the insertion of a timestamp in the client hello
   // random. When offering both TLS 1.2 and 1.3 we nevertheless comply with the
   // legacy specification.
   if(policy.include_time_in_hello_random() && (policy.allow_tls12() || policy.allow_dtls12())) {
      const uint32_t time32 = static_cast<uint32_t>(std::chrono::system_clock::to_time_t(cb.tls_current_timestamp()));

      store_be(time32, buf.data());
   }

   return buf;
}

Client_Hello_Internal::Client_Hello_Internal(const std::vector<uint8_t>& buf) {
   if(buf.size() < 41) {
      throw Decoding_Error("Client_Hello: Packet corrupted");
   }

   TLS_Data_Reader reader("ClientHello", buf);

   const uint8_t major_version = reader.get_byte();
   const uint8_t minor_version = reader.get_byte();

   m_legacy_version = Protocol_Version(major_version, minor_version);
   m_random = reader.get_fixed<uint8_t>(32);
   m_session_id = Session_ID(reader.get_range<uint8_t>(1, 0, 32));

   if(m_legacy_version.is_datagram_protocol()) {
      auto sha256 = HashFunction::create_or_throw("SHA-256");
      sha256->update(reader.get_data_read_so_far());

      m_hello_cookie = reader.get_range<uint8_t>(1, 0, 255);

      sha256->update(reader.get_remaining());
      m_cookie_input_bits = sha256->final_stdvec();
   }

   m_suites = reader.get_range_vector<uint16_t>(2, 1, 32767);
   m_comp_methods = reader.get_range_vector<uint8_t>(1, 1, 255);

   m_extensions.deserialize(reader, Connection_Side::Client, Handshake_Type::ClientHello);
}

Protocol_Version Client_Hello_Internal::version() const {
   // RFC 8446 4.2.1
   //    If [the "supported_versions"] extension is not present, servers
   //    which are compliant with this specification and which also support
   //    TLS 1.2 MUST negotiate TLS 1.2 or prior as specified in [RFC5246],
   //    even if ClientHello.legacy_version is 0x0304 or later.
   //
   // RFC 8446 4.2.1
   //    Servers MUST be prepared to receive ClientHellos that include
   //    [the supported_versions] extension but do not include 0x0304 in
   //    the list of versions.
   //
   // RFC 8446 4.1.2
   //    TLS 1.3 ClientHellos are identified as having a legacy_version of
   //    0x0303 and a supported_versions extension present with 0x0304 as
   //    the highest version indicated therein.
   if(!extensions().has<Supported_Versions>() ||
      !extensions().get<Supported_Versions>()->supports(Protocol_Version::TLS_V13)) {
      // The exact legacy_version is ignored we just inspect it to
      // distinguish TLS and DTLS.
      return (m_legacy_version.is_datagram_protocol()) ? Protocol_Version::DTLS_V12 : Protocol_Version::TLS_V12;
   }

   // Note: The Client_Hello_13 class will make sure that legacy_version
   //       is exactly 0x0303 (aka ossified TLS 1.2)
   return Protocol_Version::TLS_V13;
}

Client_Hello::Client_Hello(Client_Hello&&) noexcept = default;
Client_Hello& Client_Hello::operator=(Client_Hello&&) noexcept = default;

Client_Hello::~Client_Hello() = default;

Client_Hello::Client_Hello() : m_data(std::make_unique<Client_Hello_Internal>()) {}

/*
* Read a counterparty client hello
*/
Client_Hello::Client_Hello(std::unique_ptr<Client_Hello_Internal> data) : m_data(std::move(data)) {
   BOTAN_ASSERT_NONNULL(m_data);
}

Handshake_Type Client_Hello::type() const {
   return Handshake_Type::ClientHello;
}

Protocol_Version Client_Hello::legacy_version() const {
   return m_data->legacy_version();
}

const std::vector<uint8_t>& Client_Hello::random() const {
   return m_data->random();
}

const Session_ID& Client_Hello::session_id() const {
   return m_data->session_id();
}

const std::vector<uint8_t>& Client_Hello::compression_methods() const {
   return m_data->comp_methods();
}

const std::vector<uint16_t>& Client_Hello::ciphersuites() const {
   return m_data->ciphersuites();
}

std::set<Extension_Code> Client_Hello::extension_types() const {
   return m_data->extensions().extension_types();
}

const Extensions& Client_Hello::extensions() const {
   return m_data->extensions();
}

/*
* Serialize a Client Hello message
*/
std::vector<uint8_t> Client_Hello::serialize() const {
   std::vector<uint8_t> buf;
   buf.reserve(1024);  // working around GCC warning

   buf.push_back(m_data->legacy_version().major_version());
   buf.push_back(m_data->legacy_version().minor_version());
   buf += m_data->random();

   append_tls_length_value(buf, m_data->session_id().get(), 1);

   if(m_data->legacy_version().is_datagram_protocol()) {
      append_tls_length_value(buf, m_data->hello_cookie(), 1);
   }

   append_tls_length_value(buf, m_data->ciphersuites(), 2);
   append_tls_length_value(buf, m_data->comp_methods(), 1);

   /*
   * May not want to send extensions at all in some cases. If so,
   * should include SCSV value (if reneg info is empty, if not we are
   * renegotiating with a modern server)
   */

   buf += m_data->extensions().serialize(Connection_Side::Client);

   return buf;
}

std::vector<uint8_t> Client_Hello::cookie_input_data() const {
   BOTAN_STATE_CHECK(!m_data->hello_cookie_input_bits().empty());

   return m_data->hello_cookie_input_bits();
}

/*
* Check if we offered this ciphersuite
*/
bool Client_Hello::offered_suite(uint16_t ciphersuite) const {
   return std::find(m_data->ciphersuites().cbegin(), m_data->ciphersuites().cend(), ciphersuite) !=
          m_data->ciphersuites().cend();
}

std::vector<Signature_Scheme> Client_Hello::signature_schemes() const {
   if(const Signature_Algorithms* sigs = m_data->extensions().get<Signature_Algorithms>()) {
      return sigs->supported_schemes();
   }
   return {};
}

std::vector<Signature_Scheme> Client_Hello::certificate_signature_schemes() const {
   // RFC 8446 4.2.3
   //   If no "signature_algorithms_cert" extension is present, then the
   //   "signature_algorithms" extension also applies to signatures appearing
   //   in certificates.
   if(const Signature_Algorithms_Cert* sigs = m_data->extensions().get<Signature_Algorithms_Cert>()) {
      return sigs->supported_schemes();
   } else {
      return signature_schemes();
   }
}

std::vector<Group_Params> Client_Hello::supported_ecc_curves() const {
   if(const Supported_Groups* groups = m_data->extensions().get<Supported_Groups>()) {
      return groups->ec_groups();
   }
   return {};
}

std::vector<Group_Params> Client_Hello::supported_dh_groups() const {
   if(const Supported_Groups* groups = m_data->extensions().get<Supported_Groups>()) {
      return groups->dh_groups();
   }
   return std::vector<Group_Params>();
}

std::string Client_Hello::sni_hostname() const {
   if(const Server_Name_Indicator* sni = m_data->extensions().get<Server_Name_Indicator>()) {
      return sni->host_name();
   }
   return "";
}

std::vector<Protocol_Version> Client_Hello::supported_versions() const {
   if(const Supported_Versions* versions = m_data->extensions().get<Supported_Versions>()) {
      return versions->versions();
   }
   return {};
}

bool Client_Hello::supports_alpn() const {
   return m_data->extensions().has<Application_Layer_Protocol_Notification>();
}

bool Client_Hello::sent_signature_algorithms() const {
   return m_data->extensions().has<Signature_Algorithms>();
}

std::vector<std::string> Client_Hello::next_protocols() const {
   if(auto* alpn = m_data->extensions().get<Application_Layer_Protocol_Notification>()) {
      return alpn->protocols();
   }
   return {};
}

std::vector<uint16_t> Client_Hello::srtp_profiles() const {
   if(const SRTP_Protection_Profiles* srtp = m_data->extensions().get<SRTP_Protection_Profiles>()) {
      return srtp->profiles();
   }
   return {};
}

const std::vector<uint8_t>& Client_Hello::cookie() const {
   return m_data->hello_cookie();
}

Client_Hello_12_Shim::Client_Hello_12_Shim(std::unique_ptr<Client_Hello_Internal> data) :
      Client_Hello(std::move(data)) {}

Client_Hello_12_Shim::Client_Hello_12_Shim(const std::vector<uint8_t>& buf) :
      Client_Hello_12_Shim(std::make_unique<Client_Hello_Internal>(buf)) {}

}  // namespace Botan::TLS
