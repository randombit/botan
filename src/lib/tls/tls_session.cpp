/*
* TLS Session State
* (C) 2011-2012,2015,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_session.h>
#include <botan/internal/loadstor.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/asn1_obj.h>
#include <botan/pem.h>
#include <botan/aead.h>
#include <botan/mac.h>
#include <botan/rng.h>

#include <botan/tls_messages.h>
#include <botan/tls_callbacks.h>

#include <botan/internal/stl_util.h>

#include <utility>

namespace Botan::TLS {

void Session_Handle::validate_constraints() const
   {
   std::visit(overloaded
      {
      [](const Session_ID& id)
         {
         // RFC 5246 7.4.1.2
         //    opaque SessionID<0..32>;
         BOTAN_ARG_CHECK(!id.empty(), "Session ID must not be empty");
         BOTAN_ARG_CHECK(id.size() <= 32,
                         "Session ID cannot be longer than 32 bytes");
         },
      [](const Session_Ticket& ticket)
         {
         BOTAN_ARG_CHECK(!ticket.empty(), "Ticket most not be empty");
         BOTAN_ARG_CHECK(ticket.size() <= std::numeric_limits<uint16_t>::max(),
                         "Ticket cannot be longer than 64kB");
         },
      [](const Opaque_Session_Handle& handle)
         {
         // RFC 8446 4.6.1
         //    opaque ticket<1..2^16-1>;
         BOTAN_ARG_CHECK(!handle.empty(), "Opaque session handle must not be empty");
         BOTAN_ARG_CHECK(handle.size() <= std::numeric_limits<uint16_t>::max(),
                         "Opaque session handle cannot be longer than 64kB");
         },
      }, m_handle);
   }

Opaque_Session_Handle Session_Handle::opaque_handle() const
   {
   // both a Session_ID and a Session_Ticket could be an Opaque_Session_Handle
   return Opaque_Session_Handle(std::visit([](const auto& handle) { return handle.get(); }, m_handle));
   }

std::optional<Session_ID> Session_Handle::id() const
   {
   if(is_id())
      { return std::get<Session_ID>(m_handle); }

   // Opaque handles can mimick as a Session_ID if they are short enough
   if(is_opaque_handle())
      {
      const auto& handle = std::get<Opaque_Session_Handle>(m_handle);
      if(handle.size() <= 32)
         { return Session_ID(handle.get()); }
      }

   return std::nullopt;
   }

std::optional<Session_Ticket> Session_Handle::ticket() const
   {
   if(is_ticket())
      { return std::get<Session_Ticket>(m_handle); }

   // Opaque handles can mimick 'normal' Session_Tickets at any time
   if(is_opaque_handle())
      { return Session_Ticket(std::get<Opaque_Session_Handle>(m_handle).get()); }

   return std::nullopt;
   }


Session::Session() :
   m_start_time(std::chrono::system_clock::time_point::min()),
   m_version(),
   m_ciphersuite(0),
   m_connection_side(static_cast<Connection_Side>(0)),
   m_srtp_profile(0),
   m_extended_master_secret(false),
   m_encrypt_then_mac(false),
   m_early_data_allowed(false),
   m_max_early_data_bytes(0),
   m_ticket_age_add(0),
   m_lifetime_hint(0)
   {}

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
   m_start_time(current_timestamp),
   m_master_secret(master_secret),
   m_version(version),
   m_ciphersuite(ciphersuite),
   m_connection_side(side),
   m_srtp_profile(srtp_profile),
   m_extended_master_secret(extended_master_secret),
   m_encrypt_then_mac(encrypt_then_mac),
   m_peer_certs(certs),
   m_server_info(server_info),
   m_early_data_allowed(false),
   m_max_early_data_bytes(0),
   m_ticket_age_add(0),
   m_lifetime_hint(lifetime_hint)
   {
   BOTAN_ARG_CHECK(version.is_pre_tls_13(),
                   "Instantiated a TLS 1.2 session object with a TLS version newer than 1.2");
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
                 const Server_Information& server_info,
                 std::chrono::system_clock::time_point current_timestamp) :
   m_start_time(current_timestamp),
   m_master_secret(session_psk),
   m_version(version),
   m_ciphersuite(ciphersuite),
   m_connection_side(side),

   // TODO: Might become necessary when DTLS 1.3 is being implemented.
   m_srtp_profile(0),

   // RFC 8446 Appendix D
   //    Because TLS 1.3 always hashes in the transcript up to the server
   //    Finished, implementations which support both TLS 1.3 and earlier
   //    versions SHOULD indicate the use of the Extended Master Secret
   //    extension in their APIs whenever TLS 1.3 is used.
   m_extended_master_secret(true),

   // TLS 1.3 uses AEADs, so technically encrypt-then-MAC is not applicable.
   m_encrypt_then_mac(false),
   m_peer_certs(peer_certs),
   m_server_info(server_info),
   m_early_data_allowed(max_early_data_bytes.has_value()),
   m_max_early_data_bytes(max_early_data_bytes.value_or(0)),
   m_ticket_age_add(ticket_age_add),
   m_lifetime_hint(lifetime_hint)
   {
   BOTAN_ARG_CHECK(!version.is_pre_tls_13(),
                   "Instantiated a TLS 1.3 session object with a TLS version older than 1.3");
   }

Session::Session(secure_vector<uint8_t>&& session_psk,
                 const std::optional<uint32_t>& max_early_data_bytes,
                 std::chrono::seconds lifetime_hint,
                 const std::vector<X509_Certificate>& peer_certs,
                 const Client_Hello_13& client_hello,
                 const Server_Hello_13& server_hello,
                 Callbacks& callbacks,
                 RandomNumberGenerator& rng) :
   m_start_time(callbacks.tls_current_timestamp()),
   m_master_secret(std::move(session_psk)),
   m_version(server_hello.selected_version()),
   m_ciphersuite(server_hello.ciphersuite()),
   m_connection_side(Connection_Side::Server),
   m_extended_master_secret(true),
   m_encrypt_then_mac(true),
   m_peer_certs(peer_certs),
   m_server_info(client_hello.sni_hostname()),
   m_early_data_allowed(max_early_data_bytes.has_value()),
   m_max_early_data_bytes(max_early_data_bytes.value_or(0)),
   m_ticket_age_add(load_be<uint32_t>(rng.random_vec(4).data(), 0)),
   m_lifetime_hint(lifetime_hint)
   {
   BOTAN_ARG_CHECK(!m_version.is_pre_tls_13(),
                   "Instantiated a TLS 1.3 session object with a TLS version older than 1.3");
   }

#endif

Session::Session(const std::string& pem)
   : Session(PEM_Code::decode_check_label(pem, "TLS SESSION")) {}

Session::Session(std::span<const uint8_t> ber_data)
   {
   uint8_t side_code = 0;

   ASN1_String server_hostname;
   ASN1_String server_service;
   size_t server_port;

   ASN1_String srp_identifier_str;

   uint8_t major_version = 0, minor_version = 0;
   std::vector<uint8_t> peer_cert_bits;

   size_t start_time = 0;
   size_t srtp_profile = 0;
   size_t fragment_size = 0;
   size_t compression_method = 0;
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
        .decode_integer_type(compression_method)
        .decode_integer_type(side_code)
        .decode_integer_type(fragment_size)
        .decode(m_extended_master_secret)
        .decode(m_encrypt_then_mac)
        .decode(m_master_secret, ASN1_Type::OctetString)
        .decode_list<X509_Certificate>(m_peer_certs)
        .decode(server_hostname)
        .decode(server_service)
        .decode(server_port)
        .decode(srp_identifier_str)
        .decode(srtp_profile)
        .decode(m_early_data_allowed)
        .decode_integer_type(m_max_early_data_bytes)
        .decode_integer_type(m_ticket_age_add)
        .decode_integer_type(lifetime_hint)
      .end_cons()
      .verify_end();

   /*
   * Compression is not supported and must be zero
   */
   if(compression_method != 0)
      {
      throw Decoding_Error("Serialized TLS session contains non-null compression method");
      }

   /*
   Fragment size is not supported anymore, but the field is still
   set in the session object.
   */
   if(fragment_size != 0)
      {
      throw Decoding_Error("Serialized TLS session used maximum fragment length which is "
                           " no longer supported");
      }

   if(!Ciphersuite::by_id(ciphersuite_code))
      {
      throw Decoding_Error("Serialized TLS session contains unknown cipher suite "
                           "(" + std::to_string(ciphersuite_code) + ")");
      }

   m_ciphersuite = ciphersuite_code;
   m_version = Protocol_Version(major_version, minor_version);
   m_start_time = std::chrono::system_clock::from_time_t(start_time);
   m_connection_side = static_cast<Connection_Side>(side_code);
   m_srtp_profile = static_cast<uint16_t>(srtp_profile);

   m_server_info = Server_Information(server_hostname.value(),
                                      server_service.value(),
                                      static_cast<uint16_t>(server_port));

   m_lifetime_hint = std::chrono::seconds(lifetime_hint);
   }

secure_vector<uint8_t> Session::DER_encode() const
   {
   return DER_Encoder()
      .start_sequence()
         .encode(static_cast<size_t>(TLS_SESSION_PARAM_STRUCT_VERSION))
         .encode(static_cast<size_t>(std::chrono::system_clock::to_time_t(m_start_time)))
         .encode(static_cast<size_t>(m_version.major_version()))
         .encode(static_cast<size_t>(m_version.minor_version()))
         .encode(static_cast<size_t>(m_ciphersuite))
         .encode(static_cast<size_t>(/*old compression method*/0))
         .encode(static_cast<size_t>(m_connection_side))
         .encode(static_cast<size_t>(/*old fragment size*/0))
         .encode(m_extended_master_secret)
         .encode(m_encrypt_then_mac)
         .encode(m_master_secret, ASN1_Type::OctetString)
         .start_sequence()
            .encode_list(m_peer_certs)
         .end_cons()
         .encode(ASN1_String(m_server_info.hostname(), ASN1_Type::Utf8String))
         .encode(ASN1_String(m_server_info.service(), ASN1_Type::Utf8String))
         .encode(static_cast<size_t>(m_server_info.port()))
         .encode(ASN1_String("", ASN1_Type::Utf8String)) // old srp identifier
         .encode(static_cast<size_t>(m_srtp_profile))

         // the fields below were introduced for TLS 1.3 session tickets
         .encode(m_early_data_allowed)
         .encode(static_cast<size_t>(m_max_early_data_bytes))
         .encode(static_cast<size_t>(m_ticket_age_add))
         .encode(static_cast<size_t>(m_lifetime_hint.count()))
      .end_cons()
   .get_contents();
   }

std::string Session::PEM_encode() const
   {
   return PEM_Code::encode(this->DER_encode(), "TLS SESSION");
   }

Ciphersuite Session::ciphersuite() const
   {
   auto suite = Ciphersuite::by_id(m_ciphersuite);
   if (!suite.has_value())
      {
      throw Decoding_Error("Failed to find cipher suite for ID " +
                           std::to_string(m_ciphersuite));
      }
   return suite.value();
   }

secure_vector<uint8_t> Session::extract_master_secret()
   {
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

const size_t TLS_SESSION_CRYPT_HDR_LEN =
   TLS_SESSION_CRYPT_MAGIC_LEN +
   TLS_SESSION_CRYPT_KEY_NAME_LEN +
   TLS_SESSION_CRYPT_AEAD_NONCE_LEN +
   TLS_SESSION_CRYPT_AEAD_KEY_SEED_LEN;

const size_t TLS_SESSION_CRYPT_OVERHEAD =
   TLS_SESSION_CRYPT_HDR_LEN + TLS_SESSION_CRYPT_AEAD_TAG_SIZE;

}

std::vector<uint8_t>
Session::encrypt(const SymmetricKey& key, RandomNumberGenerator& rng) const
   {
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

   std::unique_ptr<AEAD_Mode> aead = AEAD_Mode::create_or_throw(TLS_SESSION_CRYPT_AEAD, Cipher_Dir::Encryption);
   BOTAN_ASSERT_NOMSG(aead->valid_nonce_length(TLS_SESSION_CRYPT_AEAD_NONCE_LEN));
   BOTAN_ASSERT_NOMSG(aead->tag_size() == TLS_SESSION_CRYPT_AEAD_TAG_SIZE);
   aead->set_key(aead_key);
   aead->set_associated_data_vec(buf);
   aead->start(aead_nonce);
   aead->finish(bits, 0);

   // append the ciphertext
   buf += bits;
   return buf;
   }

Session Session::decrypt(const uint8_t in[], size_t in_len, const SymmetricKey& key)
   {
   try
      {
      const size_t min_session_size = 48 + 4; // serious under-estimate
      if(in_len < TLS_SESSION_CRYPT_OVERHEAD + min_session_size)
         throw Decoding_Error("Encrypted session too short to be valid");

      const uint8_t* magic = &in[0];
      const uint8_t* key_name = magic + TLS_SESSION_CRYPT_MAGIC_LEN;
      const uint8_t* key_seed = key_name + TLS_SESSION_CRYPT_KEY_NAME_LEN;
      const uint8_t* aead_nonce = key_seed + TLS_SESSION_CRYPT_AEAD_KEY_SEED_LEN;
      const uint8_t* ctext = aead_nonce + TLS_SESSION_CRYPT_AEAD_NONCE_LEN;
      const size_t ctext_len = in_len - TLS_SESSION_CRYPT_HDR_LEN; // includes the tag

      if(load_be<uint64_t>(magic, 0) != TLS_SESSION_CRYPT_MAGIC)
         throw Decoding_Error("Missing expected magic numbers");

      auto hmac = MessageAuthenticationCode::create_or_throw(TLS_SESSION_CRYPT_HMAC);
      hmac->set_key(key);

      // First derive and check the "key name"
      std::vector<uint8_t> cmp_key_name(hmac->output_length());
      hmac->update(TLS_SESSION_CRYPT_KEY_NAME);
      hmac->final(cmp_key_name.data());

      if(same_mem(cmp_key_name.data(), key_name, TLS_SESSION_CRYPT_KEY_NAME_LEN) == false)
         throw Decoding_Error("Wrong key name for encrypted session");

      hmac->update(key_seed, TLS_SESSION_CRYPT_AEAD_KEY_SEED_LEN);
      const secure_vector<uint8_t> aead_key = hmac->final();

      auto aead = AEAD_Mode::create_or_throw(TLS_SESSION_CRYPT_AEAD, Cipher_Dir::Decryption);
      aead->set_key(aead_key);
      aead->set_associated_data(in, TLS_SESSION_CRYPT_HDR_LEN);
      aead->start(aead_nonce, TLS_SESSION_CRYPT_AEAD_NONCE_LEN);
      secure_vector<uint8_t> buf(ctext, ctext + ctext_len);
      aead->finish(buf, 0);
      return Session(buf);
      }
   catch(std::exception& e)
      {
      throw Decoding_Error("Failed to decrypt serialized TLS session: " +
                           std::string(e.what()));
      }
   }

}
