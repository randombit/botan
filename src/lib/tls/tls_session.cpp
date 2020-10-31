/*
* TLS Session State
* (C) 2011-2012,2015,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_session.h>
#include <botan/loadstor.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/asn1_obj.h>
#include <botan/pem.h>
#include <botan/aead.h>
#include <botan/mac.h>
#include <botan/rng.h>

namespace Botan {

namespace TLS {

Session::Session(const std::vector<uint8_t>& session_identifier,
                 const secure_vector<uint8_t>& master_secret,
                 Protocol_Version version,
                 uint16_t ciphersuite,
                 Connection_Side side,
                 bool extended_master_secret,
                 bool encrypt_then_mac,
                 const std::vector<X509_Certificate>& certs,
                 const std::vector<uint8_t>& ticket,
                 const Server_Information& server_info,
                 const std::string& srp_identifier,
                 uint16_t srtp_profile) :
   m_start_time(std::chrono::system_clock::now()),
   m_identifier(session_identifier),
   m_session_ticket(ticket),
   m_master_secret(master_secret),
   m_version(version),
   m_ciphersuite(ciphersuite),
   m_connection_side(side),
   m_srtp_profile(srtp_profile),
   m_extended_master_secret(extended_master_secret),
   m_encrypt_then_mac(encrypt_then_mac),
   m_peer_certs(certs),
   m_server_info(server_info),
   m_srp_identifier(srp_identifier)
   {
   }

Session::Session(const std::string& pem)
   {
   secure_vector<uint8_t> der = PEM_Code::decode_check_label(pem, "TLS SESSION");

   *this = Session(der.data(), der.size());
   }

Session::Session(const uint8_t ber[], size_t ber_len)
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

   BER_Decoder(ber, ber_len)
      .start_cons(SEQUENCE)
        .decode_and_check(static_cast<size_t>(TLS_SESSION_PARAM_STRUCT_VERSION),
                          "Unknown version in serialized TLS session")
        .decode_integer_type(start_time)
        .decode_integer_type(major_version)
        .decode_integer_type(minor_version)
        .decode(m_identifier, OCTET_STRING)
        .decode(m_session_ticket, OCTET_STRING)
        .decode_integer_type(m_ciphersuite)
        .decode_integer_type(compression_method)
        .decode_integer_type(side_code)
        .decode_integer_type(fragment_size)
        .decode(m_extended_master_secret)
        .decode(m_encrypt_then_mac)
        .decode(m_master_secret, OCTET_STRING)
        .decode(peer_cert_bits, OCTET_STRING)
        .decode(server_hostname)
        .decode(server_service)
        .decode(server_port)
        .decode(srp_identifier_str)
        .decode(srtp_profile)
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

   m_version = Protocol_Version(major_version, minor_version);
   m_start_time = std::chrono::system_clock::from_time_t(start_time);
   m_connection_side = static_cast<Connection_Side>(side_code);
   m_srtp_profile = static_cast<uint16_t>(srtp_profile);

   m_server_info = Server_Information(server_hostname.value(),
                                      server_service.value(),
                                      static_cast<uint16_t>(server_port));

   m_srp_identifier = srp_identifier_str.value();

   if(!peer_cert_bits.empty())
      {
      DataSource_Memory certs(peer_cert_bits.data(), peer_cert_bits.size());

      while(!certs.end_of_data())
         m_peer_certs.push_back(X509_Certificate(certs));
      }
   }

secure_vector<uint8_t> Session::DER_encode() const
   {
   std::vector<uint8_t> peer_cert_bits;
   for(size_t i = 0; i != m_peer_certs.size(); ++i)
      peer_cert_bits += m_peer_certs[i].BER_encode();

   return DER_Encoder()
      .start_cons(SEQUENCE)
         .encode(static_cast<size_t>(TLS_SESSION_PARAM_STRUCT_VERSION))
         .encode(static_cast<size_t>(std::chrono::system_clock::to_time_t(m_start_time)))
         .encode(static_cast<size_t>(m_version.major_version()))
         .encode(static_cast<size_t>(m_version.minor_version()))
         .encode(m_identifier, OCTET_STRING)
         .encode(m_session_ticket, OCTET_STRING)
         .encode(static_cast<size_t>(m_ciphersuite))
         .encode(static_cast<size_t>(/*old compression method*/0))
         .encode(static_cast<size_t>(m_connection_side))
         .encode(static_cast<size_t>(/*old fragment size*/0))
         .encode(m_extended_master_secret)
         .encode(m_encrypt_then_mac)
         .encode(m_master_secret, OCTET_STRING)
         .encode(peer_cert_bits, OCTET_STRING)
         .encode(ASN1_String(m_server_info.hostname(), UTF8_STRING))
         .encode(ASN1_String(m_server_info.service(), UTF8_STRING))
         .encode(static_cast<size_t>(m_server_info.port()))
         .encode(ASN1_String(m_srp_identifier, UTF8_STRING))
         .encode(static_cast<size_t>(m_srtp_profile))
      .end_cons()
   .get_contents();
   }

std::string Session::PEM_encode() const
   {
   return PEM_Code::encode(this->DER_encode(), "TLS SESSION");
   }

std::chrono::seconds Session::session_age() const
   {
   return std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now() - m_start_time);
   }

namespace {

// The output length of the HMAC must be a valid keylength for the AEAD
const char* TLS_SESSION_CRYPT_HMAC = "HMAC(SHA-512-256)";
// SIV would be better, but we can't assume it is available
const char* TLS_SESSION_CRYPT_AEAD = "AES-256/GCM";
const char* TLS_SESSION_CRYPT_KEY_NAME = "BOTAN TLS SESSION KEY NAME";
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

   std::unique_ptr<AEAD_Mode> aead = AEAD_Mode::create_or_throw(TLS_SESSION_CRYPT_AEAD, ENCRYPTION);
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

      auto aead = AEAD_Mode::create_or_throw(TLS_SESSION_CRYPT_AEAD, DECRYPTION);
      aead->set_key(aead_key);
      aead->set_associated_data(in, TLS_SESSION_CRYPT_HDR_LEN);
      aead->start(aead_nonce, TLS_SESSION_CRYPT_AEAD_NONCE_LEN);
      secure_vector<uint8_t> buf(ctext, ctext + ctext_len);
      aead->finish(buf, 0);
      return Session(buf.data(), buf.size());
      }
   catch(std::exception& e)
      {
      throw Decoding_Error("Failed to decrypt serialized TLS session: " +
                           std::string(e.what()));
      }
   }

}

}
