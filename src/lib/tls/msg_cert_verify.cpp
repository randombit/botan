/*
* Certificate Verify Message
* (C) 2004,2006,2011,2012 Jack Lloyd
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*     2021 Elektrobit Automotive GmbH
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>

#include <botan/credentials_manager.h>
#include <botan/pk_keys.h>
#include <botan/tls_algos.h>
#include <botan/tls_extensions.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_reader.h>

namespace Botan::TLS {

/*
* Create a new Certificate Verify message for TLS 1.2
*/
Certificate_Verify_12::Certificate_Verify_12(Handshake_IO& io,
                                             Handshake_State& state,
                                             const Policy& policy,
                                             RandomNumberGenerator& rng,
                                             const Private_Key* priv_key) {
   BOTAN_ASSERT_NONNULL(priv_key);

   std::pair<std::string, Signature_Format> format = state.choose_sig_format(*priv_key, m_scheme, true, policy);

   m_signature =
      state.callbacks().tls_sign_message(*priv_key, rng, format.first, format.second, state.hash().get_contents());

   state.hash().update(io.send(*this));
}

/*
* Deserialize a Certificate Verify message
*/
Certificate_Verify::Certificate_Verify(const std::vector<uint8_t>& buf) {
   TLS_Data_Reader reader("CertificateVerify", buf);

   m_scheme = Signature_Scheme(reader.get_uint16_t());
   m_signature = reader.get_range<uint8_t>(2, 0, 65535);
   reader.assert_done();

   if(!m_scheme.is_set()) {
      throw Decoding_Error("Counterparty did not send hash/sig IDS");
   }
}

/*
* Serialize a Certificate Verify message
*/
std::vector<uint8_t> Certificate_Verify::serialize() const {
   BOTAN_ASSERT_NOMSG(m_scheme.is_set());
   std::vector<uint8_t> buf;
   buf.reserve(2 + 2 + m_signature.size());  // work around GCC warning

   const auto code = m_scheme.wire_code();
   buf.push_back(get_byte<0>(code));
   buf.push_back(get_byte<1>(code));

   if(m_signature.size() > 0xFFFF) {
      throw Encoding_Error("Certificate_Verify signature too long to encode");
   }

   const uint16_t sig_len = static_cast<uint16_t>(m_signature.size());
   buf.push_back(get_byte<0>(sig_len));
   buf.push_back(get_byte<1>(sig_len));
   buf += m_signature;

   return buf;
}

bool Certificate_Verify_12::verify(const X509_Certificate& cert,
                                   const Handshake_State& state,
                                   const Policy& policy) const {
   auto key = cert.subject_public_key();

   policy.check_peer_key_acceptable(*key);

   std::pair<std::string, Signature_Format> format =
      state.parse_sig_format(*key, m_scheme, state.client_hello()->signature_schemes(), true, policy);

   const bool signature_valid =
      state.callbacks().tls_verify_message(*key, format.first, format.second, state.hash().get_contents(), m_signature);

#if defined(BOTAN_UNSAFE_FUZZER_MODE)
   BOTAN_UNUSED(signature_valid);
   return true;

#else
   return signature_valid;

#endif
}

#if defined(BOTAN_HAS_TLS_13)

namespace {

std::vector<uint8_t> message(Connection_Side side, const Transcript_Hash& hash) {
   std::vector<uint8_t> msg(64, 0x20);
   msg.reserve(64 + 33 + 1 + hash.size());

   const std::string context_string = (side == TLS::Connection_Side::Server) ? "TLS 1.3, server CertificateVerify"
                                                                             : "TLS 1.3, client CertificateVerify";

   msg.insert(msg.end(), context_string.cbegin(), context_string.cend());
   msg.push_back(0x00);

   msg.insert(msg.end(), hash.cbegin(), hash.cend());
   return msg;
}

Signature_Scheme choose_signature_scheme(const Private_Key& key,
                                         const std::vector<Signature_Scheme>& allowed_schemes,
                                         const std::vector<Signature_Scheme>& peer_allowed_schemes) {
   for(Signature_Scheme scheme : allowed_schemes) {
      if(scheme.is_available() && scheme.is_suitable_for(key) && value_exists(peer_allowed_schemes, scheme)) {
         return scheme;
      }
   }

   throw TLS_Exception(Alert::HandshakeFailure, "Failed to agree on a signature algorithm");
}

}  // namespace

/*
* Create a new Certificate Verify message for TLS 1.3
*/
Certificate_Verify_13::Certificate_Verify_13(const Certificate_13& certificate_msg,
                                             const std::vector<Signature_Scheme>& peer_allowed_schemes,
                                             std::string_view hostname,
                                             const Transcript_Hash& hash,
                                             Connection_Side whoami,
                                             Credentials_Manager& creds_mgr,
                                             const Policy& policy,
                                             Callbacks& callbacks,
                                             RandomNumberGenerator& rng) :
      m_side(whoami) {
   BOTAN_ASSERT_NOMSG(!certificate_msg.empty());

   const auto op_type = (m_side == Connection_Side::Client) ? "tls-client" : "tls-server";
   const auto context = std::string(hostname);

   const auto private_key = (certificate_msg.has_certificate_chain())
                               ? creds_mgr.private_key_for(certificate_msg.leaf(), op_type, context)
                               : creds_mgr.private_key_for(*certificate_msg.public_key(), op_type, context);
   if(!private_key) {
      throw TLS_Exception(Alert::InternalError, "Application did not provide a private key for its credential");
   }

   m_scheme = choose_signature_scheme(*private_key, policy.allowed_signature_schemes(), peer_allowed_schemes);
   BOTAN_ASSERT_NOMSG(m_scheme.is_available());
   BOTAN_ASSERT_NOMSG(m_scheme.is_compatible_with(Protocol_Version::TLS_V13));

   m_signature = callbacks.tls_sign_message(
      *private_key, rng, m_scheme.padding_string(), m_scheme.format().value(), message(m_side, hash));
}

Certificate_Verify_13::Certificate_Verify_13(const std::vector<uint8_t>& buf, const Connection_Side side) :
      Certificate_Verify(buf), m_side(side) {
   if(!m_scheme.is_available()) {
      throw TLS_Exception(Alert::HandshakeFailure, "Peer sent unknown signature scheme");
   }

   if(!m_scheme.is_compatible_with(Protocol_Version::TLS_V13)) {
      throw TLS_Exception(Alert::IllegalParameter, "Peer sent signature algorithm that is not suitable for TLS 1.3");
   }
}

/*
* Verify a Certificate Verify message
*/
bool Certificate_Verify_13::verify(const Public_Key& public_key,
                                   Callbacks& callbacks,
                                   const Transcript_Hash& transcript_hash) const {
   BOTAN_ASSERT_NOMSG(m_scheme.is_available());

   // RFC 8446 4.2.3
   //    The keys found in certificates MUST [...] be of appropriate type for
   //    the signature algorithms they are used with.
   if(m_scheme.key_algorithm_identifier() != public_key.algorithm_identifier()) {
      throw TLS_Exception(Alert::IllegalParameter, "Signature algorithm does not match certificate's public key");
   }

   const bool signature_valid = callbacks.tls_verify_message(
      public_key, m_scheme.padding_string(), m_scheme.format().value(), message(m_side, transcript_hash), m_signature);

   #if defined(BOTAN_UNSAFE_FUZZER_MODE)
   BOTAN_UNUSED(signature_valid);
   return true;
   #else
   return signature_valid;
   #endif
}

#endif  // BOTAN_HAS_TLS_13

}  // namespace Botan::TLS
