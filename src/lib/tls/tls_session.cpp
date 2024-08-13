/*
* TLS Session State
* (C) 2011-2012,2015,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_session.h>

#include <botan/aead.h>
#include <botan/asn1_obj.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/mac.h>
#include <botan/pem.h>
#include <botan/rng.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_messages.h>
#include <botan/x509_key.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>

#include <utility>

namespace Botan::TLS {

void Session_Handle::validate_constraints() const {
   std::visit(overloaded{
                 [](const Session_ID& id) {
                    // RFC 5246 7.4.1.2
                    //    opaque SessionID<0..32>;
                    BOTAN_ARG_CHECK(!id.empty(), "Session ID must not be empty");
                    BOTAN_ARG_CHECK(id.size() <= 32, "Session ID cannot be longer than 32 bytes");
                 },
                 [](const Session_Ticket& ticket) {
                    BOTAN_ARG_CHECK(!ticket.empty(), "Ticket most not be empty");
                    BOTAN_ARG_CHECK(ticket.size() <= std::numeric_limits<uint16_t>::max(),
                                    "Ticket cannot be longer than 64kB");
                 },
                 [](const Opaque_Session_Handle& handle) {
                    // RFC 8446 4.6.1
                    //    opaque ticket<1..2^16-1>;
                    BOTAN_ARG_CHECK(!handle.empty(), "Opaque session handle must not be empty");
                    BOTAN_ARG_CHECK(handle.size() <= std::numeric_limits<uint16_t>::max(),
                                    "Opaque session handle cannot be longer than 64kB");
                 },
              },
              m_handle);
}

Opaque_Session_Handle Session_Handle::opaque_handle() const {
   // both a Session_ID and a Session_Ticket could be an Opaque_Session_Handle
   return Opaque_Session_Handle(std::visit([](const auto& handle) { return handle.get(); }, m_handle));
}

std::optional<Session_ID> Session_Handle::id() const {
   if(is_id()) {
      return std::get<Session_ID>(m_handle);
   }

   // Opaque handles can mimick as a Session_ID if they are short enough
   if(is_opaque_handle()) {
      const auto& handle = std::get<Opaque_Session_Handle>(m_handle);
      if(handle.size() <= 32) {
         return Session_ID(handle.get());
      }
   }

   return std::nullopt;
}

std::optional<Session_Ticket> Session_Handle::ticket() const {
   if(is_ticket()) {
      return std::get<Session_Ticket>(m_handle);
   }

   // Opaque handles can mimick 'normal' Session_Tickets at any time
   if(is_opaque_handle()) {
      return Session_Ticket(std::get<Opaque_Session_Handle>(m_handle).get());
   }

   return std::nullopt;
}

Ciphersuite Session_Base::ciphersuite() const {
   auto suite = Ciphersuite::by_id(m_ciphersuite);
   if(!suite.has_value()) {
      throw Decoding_Error("Failed to find cipher suite for ID " + std::to_string(m_ciphersuite));
   }
   return suite.value();
}

Session_Summary::Session_Summary(const Session_Base& base,
                                 bool was_resumption,
                                 std::optional<std::string> psk_identity) :
      Session_Base(base), m_external_psk_identity(std::move(psk_identity)), m_was_resumption(was_resumption) {
   BOTAN_ARG_CHECK(version().is_pre_tls_13(), "Instantiated a TLS 1.2 session summary with an newer TLS version");

   const auto cs = ciphersuite();
   m_kex_algo = cs.kex_algo();
}

#if defined(BOTAN_HAS_TLS_13)

namespace {

std::string tls13_kex_to_string(bool psk, const Named_Group& group) {
   if(psk) {
      if(group.is_dh_named_group()) {
         return kex_method_to_string(Kex_Algo::DHE_PSK);
      } else if(group.is_pure_ecc_group()) {
         return kex_method_to_string(Kex_Algo::ECDHE_PSK);
      } else if(group.is_kem() && !group.is_pqc_hybrid()) {
         return kex_method_to_string(Kex_Algo::KEM_PSK);
      } else if(group.is_pqc_hybrid()) {
         return kex_method_to_string(Kex_Algo::HYBRID_PSK);
      } else if(auto s = group.to_string()) {
         return *s;
      }
   } else {
      if(group.is_dh_named_group()) {
         return kex_method_to_string(Kex_Algo::DH);
      } else if(group.is_pure_ecc_group()) {
         return kex_method_to_string(Kex_Algo::ECDH);
      } else if(group.is_kem() && !group.is_pqc_hybrid()) {
         return kex_method_to_string(Kex_Algo::KEM);
      } else if(group.is_pqc_hybrid()) {
         return kex_method_to_string(Kex_Algo::HYBRID);
      } else if(auto s = group.to_string()) {
         return *s;
      }
   }

   return kex_method_to_string(Kex_Algo::UNDEFINED);
}

}  // namespace

Session_Summary::Session_Summary(const Server_Hello_13& server_hello,
                                 Connection_Side side,
                                 std::vector<X509_Certificate> peer_certs,
                                 std::shared_ptr<const Public_Key> peer_raw_public_key,
                                 std::optional<std::string> psk_identity,
                                 bool session_was_resumed,
                                 Server_Information server_info,
                                 std::chrono::system_clock::time_point current_timestamp) :
      Session_Base(current_timestamp,
                   server_hello.selected_version(),
                   server_hello.ciphersuite(),
                   side,

                   // TODO: SRTP might become necessary when DTLS 1.3 is being implemented
                   0,

                   // RFC 8446 Appendix D
                   //    Because TLS 1.3 always hashes in the transcript up to the server
                   //    Finished, implementations which support both TLS 1.3 and earlier
                   //    versions SHOULD indicate the use of the Extended Master Secret
                   //    extension in their APIs whenever TLS 1.3 is used.
                   true,

                   // TLS 1.3 uses AEADs, so technically encrypt-then-MAC is not applicable.
                   false,
                   std::move(peer_certs),
                   std::move(peer_raw_public_key),
                   std::move(server_info)),
      m_external_psk_identity(std::move(psk_identity)),
      m_was_resumption(session_was_resumed) {
   BOTAN_ARG_CHECK(version().is_tls_13_or_later(), "Instantiated a TLS 1.3 session summary with an older TLS version");
   set_session_id(server_hello.session_id());

   // In TLS 1.3 the key exchange algorithm is not negotiated in the ciphersuite
   // anymore. This provides a compatible identifier for applications to use.

   const auto group = [&]() -> std::optional<Named_Group> {
      if(const auto keyshare = server_hello.extensions().get<Key_Share>()) {
         return keyshare->selected_group();
      } else {
         return {};
      }
   }();

   if(group.has_value()) {
      m_kex_parameters = group->to_string();
      m_kex_algo = tls13_kex_to_string(psk_used() || was_resumption(), group.value());
   } else {
      BOTAN_ASSERT(psk_used() || was_resumption(), "Missing key share during non-PSK negotation");
      m_kex_algo = kex_method_to_string(Kex_Algo::PSK);
   }
}

#endif

Session::Session(const secure_vector<uint8_t>& master_secret,
                 Protocol_Version version,
                 uint16_t ciphersuite,
                 Connection_Side side,
                 bool extended_master_secret,
                 bool encrypt_then_mac,
                 const std::vector<X509_Certificate>& certs,
                 const Server_Information& server_info,
                 uint16_t srtp_profile,
                 std::chrono::system_clock::time_point current_timestamp,
                 std::chrono::seconds lifetime_hint) :
      Session_Base(current_timestamp,
                   version,
                   ciphersuite,
                   side,
                   srtp_profile,
                   extended_master_secret,
                   encrypt_then_mac,
                   certs,
                   nullptr,  // RFC 7250 (raw public keys) is NYI for TLS 1.2
                   server_info),
      m_master_secret(master_secret),
      m_early_data_allowed(false),
      m_max_early_data_bytes(0),
      m_ticket_age_add(0),
      m_lifetime_hint(lifetime_hint) {
   BOTAN_ARG_CHECK(version.is_pre_tls_13(), "Instantiated a TLS 1.2 session object with a TLS version newer than 1.2");
}

#if defined(BOTAN_HAS_TLS_13)

Session::Session(const secure_vector<uint8_t>& session_psk,
                 const std::optional<uint32_t>& max_early_data_bytes,
                 uint32_t ticket_age_add,
                 std::chrono::seconds lifetime_hint,
                 Protocol_Version version,
                 uint16_t ciphersuite,
                 Connection_Side side,
                 const std::vector<X509_Certificate>& peer_certs,
                 std::shared_ptr<const Public_Key> peer_raw_public_key,
                 const Server_Information& server_info,
                 std::chrono::system_clock::time_point current_timestamp) :
      Session_Base(current_timestamp,
                   version,
                   ciphersuite,
                   side,

                   // TODO: SRTP might become necessary when DTLS 1.3 is being implemented
                   0,

                   // RFC 8446 Appendix D
                   //    Because TLS 1.3 always hashes in the transcript up to the server
                   //    Finished, implementations which support both TLS 1.3 and earlier
                   //    versions SHOULD indicate the use of the Extended Master Secret
                   //    extension in their APIs whenever TLS 1.3 is used.
                   true,

                   // TLS 1.3 uses AEADs, so technically encrypt-then-MAC is not applicable.
                   false,
                   peer_certs,
                   std::move(peer_raw_public_key),
                   server_info),
      m_master_secret(session_psk),
      m_early_data_allowed(max_early_data_bytes.has_value()),
      m_max_early_data_bytes(max_early_data_bytes.value_or(0)),
      m_ticket_age_add(ticket_age_add),
      m_lifetime_hint(lifetime_hint) {
   BOTAN_ARG_CHECK(!version.is_pre_tls_13(), "Instantiated a TLS 1.3 session object with a TLS version older than 1.3");
}

Session::Session(secure_vector<uint8_t>&& session_psk,
                 const std::optional<uint32_t>& max_early_data_bytes,
                 std::chrono::seconds lifetime_hint,
                 const std::vector<X509_Certificate>& peer_certs,
                 std::shared_ptr<const Public_Key> peer_raw_public_key,
                 const Client_Hello_13& client_hello,
                 const Server_Hello_13& server_hello,
                 Callbacks& callbacks,
                 RandomNumberGenerator& rng) :
      Session_Base(callbacks.tls_current_timestamp(),
                   server_hello.selected_version(),
                   server_hello.ciphersuite(),
                   Connection_Side::Server,
                   0,
                   true,
                   false,  // see constructor above for rationales
                   peer_certs,
                   std::move(peer_raw_public_key),
                   Server_Information(client_hello.sni_hostname())),
      m_master_secret(std::move(session_psk)),
      m_early_data_allowed(max_early_data_bytes.has_value()),
      m_max_early_data_bytes(max_early_data_bytes.value_or(0)),
      m_ticket_age_add(load_be<uint32_t>(rng.random_vec(4).data(), 0)),
      m_lifetime_hint(lifetime_hint) {
   BOTAN_ARG_CHECK(!m_version.is_pre_tls_13(),
                   "Instantiated a TLS 1.3 session object with a TLS version older than 1.3");
}

#endif

Session::Session(std::string_view pem) : Session(PEM_Code::decode_check_label(pem, "TLS SESSION")) {}

Session::Session(std::span<const uint8_t> ber_data) {
   uint8_t side_code = 0;

   std::vector<uint8_t> raw_pubkey_or_empty;

   ASN1_String server_hostname;
   ASN1_String server_service;
   size_t server_port;

   uint8_t major_version = 0, minor_version = 0;

   size_t start_time = 0;
   size_t srtp_profile = 0;
   uint16_t ciphersuite_code = 0;
   uint64_t lifetime_hint = 0;

   BER_Decoder(ber_data.data(), ber_data.size())
      .start_sequence()
      .decode_and_check(static_cast<size_t>(TLS_SESSION_PARAM_STRUCT_VERSION),
                        "Unknown version in serialized TLS session")
      .decode_integer_type(start_time)
      .decode_integer_type(major_version)
      .decode_integer_type(minor_version)
      .decode_integer_type(ciphersuite_code)
      .decode_integer_type(side_code)
      .decode(m_extended_master_secret)
      .decode(m_encrypt_then_mac)
      .decode(m_master_secret, ASN1_Type::OctetString)
      .decode_list<X509_Certificate>(m_peer_certs)
      .decode(raw_pubkey_or_empty, ASN1_Type::OctetString)
      .decode(server_hostname)
      .decode(server_service)
      .decode(server_port)
      .decode(srtp_profile)
      .decode(m_early_data_allowed)
      .decode_integer_type(m_max_early_data_bytes)
      .decode_integer_type(m_ticket_age_add)
      .decode_integer_type(lifetime_hint)
      .end_cons()
      .verify_end();

   if(!Ciphersuite::by_id(ciphersuite_code)) {
      throw Decoding_Error(
         "Serialized TLS session contains unknown cipher suite "
         "(" +
         std::to_string(ciphersuite_code) + ")");
   }

   m_ciphersuite = ciphersuite_code;
   m_version = Protocol_Version(major_version, minor_version);
   m_start_time = std::chrono::system_clock::from_time_t(start_time);
   m_connection_side = static_cast<Connection_Side>(side_code);
   m_srtp_profile = static_cast<uint16_t>(srtp_profile);

   m_server_info =
      Server_Information(server_hostname.value(), server_service.value(), static_cast<uint16_t>(server_port));

   if(!raw_pubkey_or_empty.empty()) {
      m_peer_raw_public_key = X509::load_key(raw_pubkey_or_empty);
   }

   m_lifetime_hint = std::chrono::seconds(lifetime_hint);
}

secure_vector<uint8_t> Session::DER_encode() const {
   const auto raw_pubkey_or_empty =
      m_peer_raw_public_key ? m_peer_raw_public_key->subject_public_key() : std::vector<uint8_t>{};

   return DER_Encoder()
      .start_sequence()
      .encode(static_cast<size_t>(TLS_SESSION_PARAM_STRUCT_VERSION))
      .encode(static_cast<size_t>(std::chrono::system_clock::to_time_t(m_start_time)))
      .encode(static_cast<size_t>(m_version.major_version()))
      .encode(static_cast<size_t>(m_version.minor_version()))
      .encode(static_cast<size_t>(m_ciphersuite))
      .encode(static_cast<size_t>(m_connection_side))
      .encode(m_extended_master_secret)
      .encode(m_encrypt_then_mac)
      .encode(m_master_secret, ASN1_Type::OctetString)
      .start_sequence()
      .encode_list(m_peer_certs)
      .end_cons()
      .encode(raw_pubkey_or_empty, ASN1_Type::OctetString)
      .encode(ASN1_String(m_server_info.hostname(), ASN1_Type::Utf8String))
      .encode(ASN1_String(m_server_info.service(), ASN1_Type::Utf8String))
      .encode(static_cast<size_t>(m_server_info.port()))
      .encode(static_cast<size_t>(m_srtp_profile))

      // the fields below were introduced for TLS 1.3 session tickets
      .encode(m_early_data_allowed)
      .encode(static_cast<size_t>(m_max_early_data_bytes))
      .encode(static_cast<size_t>(m_ticket_age_add))
      .encode(static_cast<size_t>(m_lifetime_hint.count()))
      .end_cons()
      .get_contents();
}

std::string Session::PEM_encode() const {
   return PEM_Code::encode(this->DER_encode(), "TLS SESSION");
}

secure_vector<uint8_t> Session::extract_master_secret() {
   BOTAN_STATE_CHECK(!m_master_secret.empty());
   return std::exchange(m_master_secret, {});
}

namespace {

// The output length of the HMAC must be a valid keylength for the AEAD
const char* const TLS_SESSION_CRYPT_HMAC = "HMAC(SHA-512-256)";
// SIV would be better, but we can't assume it is available
const char* const TLS_SESSION_CRYPT_AEAD = "AES-256/GCM";
const char* const TLS_SESSION_CRYPT_KEY_NAME = "BOTAN TLS SESSION KEY NAME";
const uint64_t TLS_SESSION_CRYPT_MAGIC = 0x068B5A9D396C0000;
const size_t TLS_SESSION_CRYPT_MAGIC_LEN = 8;
const size_t TLS_SESSION_CRYPT_KEY_NAME_LEN = 4;
const size_t TLS_SESSION_CRYPT_AEAD_NONCE_LEN = 12;
const size_t TLS_SESSION_CRYPT_AEAD_KEY_SEED_LEN = 16;
const size_t TLS_SESSION_CRYPT_AEAD_TAG_SIZE = 16;

const size_t TLS_SESSION_CRYPT_HDR_LEN = TLS_SESSION_CRYPT_MAGIC_LEN + TLS_SESSION_CRYPT_KEY_NAME_LEN +
                                         TLS_SESSION_CRYPT_AEAD_NONCE_LEN + TLS_SESSION_CRYPT_AEAD_KEY_SEED_LEN;

const size_t TLS_SESSION_CRYPT_OVERHEAD = TLS_SESSION_CRYPT_HDR_LEN + TLS_SESSION_CRYPT_AEAD_TAG_SIZE;

}  // namespace

std::vector<uint8_t> Session::encrypt(const SymmetricKey& key, RandomNumberGenerator& rng) const {
   auto hmac = MessageAuthenticationCode::create_or_throw(TLS_SESSION_CRYPT_HMAC);
   hmac->set_key(key);

   // First derive the "key name"
   std::vector<uint8_t> key_name(hmac->output_length());
   hmac->update(TLS_SESSION_CRYPT_KEY_NAME);
   hmac->final(key_name.data());
   key_name.resize(TLS_SESSION_CRYPT_KEY_NAME_LEN);

   std::vector<uint8_t> aead_nonce;
   std::vector<uint8_t> key_seed;

   rng.random_vec(aead_nonce, TLS_SESSION_CRYPT_AEAD_NONCE_LEN);
   rng.random_vec(key_seed, TLS_SESSION_CRYPT_AEAD_KEY_SEED_LEN);

   hmac->update(key_seed);
   const secure_vector<uint8_t> aead_key = hmac->final();

   secure_vector<uint8_t> bits = this->DER_encode();

   // create the header
   std::vector<uint8_t> buf;
   buf.reserve(TLS_SESSION_CRYPT_OVERHEAD + bits.size());
   buf.resize(TLS_SESSION_CRYPT_MAGIC_LEN);
   store_be(TLS_SESSION_CRYPT_MAGIC, &buf[0]);
   buf += key_name;
   buf += key_seed;
   buf += aead_nonce;

   auto aead = AEAD_Mode::create_or_throw(TLS_SESSION_CRYPT_AEAD, Cipher_Dir::Encryption);
   BOTAN_ASSERT_NOMSG(aead->valid_nonce_length(TLS_SESSION_CRYPT_AEAD_NONCE_LEN));
   BOTAN_ASSERT_NOMSG(aead->tag_size() == TLS_SESSION_CRYPT_AEAD_TAG_SIZE);
   aead->set_key(aead_key);
   aead->set_associated_data(buf);
   aead->start(aead_nonce);
   aead->finish(bits, 0);

   // append the ciphertext
   buf += bits;
   return buf;
}

Session Session::decrypt(std::span<const uint8_t> in, const SymmetricKey& key) {
   try {
      const size_t min_session_size = 48 + 4;  // serious under-estimate
      if(in.size() < TLS_SESSION_CRYPT_OVERHEAD + min_session_size) {
         throw Decoding_Error("Encrypted session too short to be valid");
      }

      BufferSlicer sub(in);
      const auto magic = sub.take(TLS_SESSION_CRYPT_MAGIC_LEN).data();
      const auto key_name = sub.take(TLS_SESSION_CRYPT_KEY_NAME_LEN).data();
      const auto key_seed = sub.take(TLS_SESSION_CRYPT_AEAD_KEY_SEED_LEN).data();
      const auto aead_nonce = sub.take(TLS_SESSION_CRYPT_AEAD_NONCE_LEN).data();
      auto ctext = sub.copy_as_secure_vector(sub.remaining());

      if(load_be<uint64_t>(magic, 0) != TLS_SESSION_CRYPT_MAGIC) {
         throw Decoding_Error("Missing expected magic numbers");
      }

      auto hmac = MessageAuthenticationCode::create_or_throw(TLS_SESSION_CRYPT_HMAC);
      hmac->set_key(key);

      // First derive and check the "key name"
      std::vector<uint8_t> cmp_key_name(hmac->output_length());
      hmac->update(TLS_SESSION_CRYPT_KEY_NAME);
      hmac->final(cmp_key_name.data());

      if(CT::is_equal(cmp_key_name.data(), key_name, TLS_SESSION_CRYPT_KEY_NAME_LEN).as_bool() == false) {
         throw Decoding_Error("Wrong key name for encrypted session");
      }

      hmac->update(key_seed, TLS_SESSION_CRYPT_AEAD_KEY_SEED_LEN);
      const secure_vector<uint8_t> aead_key = hmac->final();

      auto aead = AEAD_Mode::create_or_throw(TLS_SESSION_CRYPT_AEAD, Cipher_Dir::Decryption);
      aead->set_key(aead_key);
      aead->set_associated_data(in.data(), TLS_SESSION_CRYPT_HDR_LEN);
      aead->start(aead_nonce, TLS_SESSION_CRYPT_AEAD_NONCE_LEN);
      aead->finish(ctext, 0);
      return Session(ctext);
   } catch(std::exception& e) {
      throw Decoding_Error("Failed to decrypt serialized TLS session: " + std::string(e.what()));
   }
}

}  // namespace Botan::TLS
