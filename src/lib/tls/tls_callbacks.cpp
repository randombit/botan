/*
* TLS Callbacks
* (C) 2016 Jack Lloyd
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*     2023 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_callbacks.h>
#include <botan/tls_crypto_operations.h>

#include <botan/assert.h>
#include <botan/dl_group.h>
#include <botan/ocsp.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>
#include <botan/tls_session.h>
#include <botan/x509path.h>

namespace Botan {

void TLS::Callbacks::tls_inspect_handshake_msg(const Handshake_Message& /*unused*/) {
   // default is no op
}

std::string TLS::Callbacks::tls_server_choose_app_protocol(const std::vector<std::string>& /*unused*/) {
   return "";
}

std::string TLS::Callbacks::tls_peer_network_identity() {
   return "";
}

std::chrono::system_clock::time_point TLS::Callbacks::tls_current_timestamp() {
   return std::chrono::system_clock::now();
}

uint64_t TLS::Callbacks::tls_current_monotonic_clock_ms() {
   const auto now = std::chrono::steady_clock::now().time_since_epoch();
   return std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}

void TLS::Callbacks::tls_modify_extensions(Extensions& /*unused*/,
                                           Connection_Side /*unused*/,
                                           Handshake_Type /*unused*/) {}

void TLS::Callbacks::tls_examine_extensions(const Extensions& /*unused*/,
                                            Connection_Side /*unused*/,
                                            Handshake_Type /*unused*/) {}

bool TLS::Callbacks::tls_should_persist_resumption_information(const Session& session) {
   // RFC 5077 3.3
   //    The ticket_lifetime_hint field contains a hint from the server about
   //    how long the ticket should be stored. A value of zero is reserved to
   //    indicate that the lifetime of the ticket is unspecified.
   //
   // RFC 8446 4.6.1
   //    [A ticket_lifetime] of zero indicates that the ticket should be discarded
   //    immediately.
   //
   // By default we opt to keep all sessions, except for TLS 1.3 with a lifetime
   // hint of zero.
   return session.lifetime_hint().count() > 0 || session.version().is_pre_tls_13();
}

void TLS::Callbacks::tls_verify_cert_chain(const std::vector<X509_Certificate>& cert_chain,
                                           const std::vector<std::optional<OCSP::Response>>& ocsp_responses,
                                           const std::vector<Certificate_Store*>& trusted_roots,
                                           Usage_Type usage,
                                           std::string_view hostname,
                                           const TLS::Policy& policy) {
   if(cert_chain.empty()) {
      throw Invalid_Argument("Certificate chain was empty");
   }

   const Path_Validation_Restrictions restrictions(policy.require_cert_revocation_info(),
                                                   policy.minimum_signature_strength());

   /*
   Hostname is always provided in order to allow host-specific logic if required,
   but it should not be passed to x509_path_validate unless we are verifying
   the server.
   */
   const std::string_view name_to_match = (usage == Usage_Type::TLS_CLIENT_AUTH) ? std::string_view{} : hostname;

   const Path_Validation_Result result = x509_path_validate(cert_chain,
                                                            restrictions,
                                                            trusted_roots,
                                                            name_to_match,
                                                            usage,
                                                            tls_current_timestamp(),
                                                            tls_verify_cert_chain_ocsp_timeout(),
                                                            ocsp_responses);

   if(!result.successful_validation()) {
      throw TLS_Exception(Alert::BadCertificate, "Certificate validation failure: " + result.result_string());
   }
}

void TLS::Callbacks::tls_verify_raw_public_key(const Public_Key& raw_public_key,
                                               Usage_Type usage,
                                               std::string_view hostname,
                                               const TLS::Policy& policy) {
   BOTAN_UNUSED(raw_public_key, usage, hostname, policy);
   // There is no good default implementation for authenticating raw public key.
   // Applications that wish to use them for authentication, must override this.
   throw TLS_Exception(Alert::CertificateUnknown, "Application did not provide a means to validate the raw public key");
}

std::optional<OCSP::Response> TLS::Callbacks::tls_parse_ocsp_response(const std::vector<uint8_t>& raw_response) {
   try {
      return OCSP::Response(raw_response);
   } catch(const Decoding_Error&) {
      // ignore parsing errors and just ignore the broken OCSP response
      return std::nullopt;
   }
}

std::vector<std::vector<uint8_t>> TLS::Callbacks::tls_provide_cert_chain_status(
   const std::vector<X509_Certificate>& chain, const Certificate_Status_Request& csr) {
   std::vector<std::vector<uint8_t>> result(chain.size());
   if(!chain.empty()) {
      result[0] = tls_provide_cert_status(chain, csr);
   }
   return result;
}

std::vector<uint8_t> TLS::Callbacks::tls_sign_message(const Private_Key& key,
                                                      RandomNumberGenerator& rng,
                                                      std::string_view padding,
                                                      Signature_Format format,
                                                      const std::vector<uint8_t>& msg) {
   return TLS::DefaultCryptoOperations(*this).CryptoOperations::sign_message(key, rng, padding, format, msg);
}

bool TLS::Callbacks::tls_verify_message(const Public_Key& key,
                                        std::string_view padding,
                                        Signature_Format format,
                                        const std::vector<uint8_t>& msg,
                                        const std::vector<uint8_t>& sig) {
   return TLS::DefaultCryptoOperations(*this).CryptoOperations::verify_message(key, padding, format, msg, sig);
}

std::unique_ptr<Public_Key> TLS::Callbacks::tls_deserialize_peer_public_key(
   const std::variant<TLS::Group_Params, DL_Group>& group, std::span<const uint8_t> key_bits) {
   return TLS::DefaultCryptoOperations(*this).CryptoOperations::deserialize_peer_public_key(group, key_bits);
}

std::unique_ptr<Private_Key> TLS::Callbacks::tls_kem_generate_key(TLS::Group_Params group, RandomNumberGenerator& rng) {
   return TLS::DefaultCryptoOperations(*this).CryptoOperations::kem_generate_key(group, rng);
}

KEM_Encapsulation TLS::Callbacks::tls_kem_encapsulate(TLS::Group_Params group,
                                                      const std::vector<uint8_t>& encoded_public_key,
                                                      RandomNumberGenerator& rng,
                                                      const Policy& policy) {
   return TLS::DefaultCryptoOperations(*this).CryptoOperations::kem_encapsulate(group, encoded_public_key, rng, policy);
}

secure_vector<uint8_t> TLS::Callbacks::tls_kem_decapsulate(TLS::Group_Params group,
                                                           const Private_Key& private_key,
                                                           const std::vector<uint8_t>& encapsulated_bytes,
                                                           RandomNumberGenerator& rng,
                                                           const Policy& policy) {
   return TLS::DefaultCryptoOperations(*this).CryptoOperations::kem_decapsulate(
      group, private_key, encapsulated_bytes, rng, policy);
}

std::unique_ptr<PK_Key_Agreement_Key> TLS::Callbacks::tls_generate_ephemeral_key(
   const std::variant<TLS::Group_Params, DL_Group>& group, RandomNumberGenerator& rng) {
   return TLS::DefaultCryptoOperations(*this).CryptoOperations::generate_ephemeral_key(group, rng);
}

std::unique_ptr<PK_Key_Agreement_Key> TLS::Callbacks::tls12_generate_ephemeral_ecdh_key(
   TLS::Group_Params group, RandomNumberGenerator& rng, EC_Point_Format tls12_ecc_pubkey_encoding_format) {
   return TLS::DefaultCryptoOperations(*this).CryptoOperations::tls12_generate_ephemeral_ecdh_key(
      group, rng, tls12_ecc_pubkey_encoding_format);
}

secure_vector<uint8_t> TLS::Callbacks::tls_ephemeral_key_agreement(
   const std::variant<TLS::Group_Params, DL_Group>& group,
   const PK_Key_Agreement_Key& private_key,
   const std::vector<uint8_t>& public_value,
   RandomNumberGenerator& rng,
   const Policy& policy) {
   return TLS::DefaultCryptoOperations(*this).CryptoOperations::ephemeral_key_agreement(
      group, private_key, public_value, rng, policy);
}

std::unique_ptr<KDF> TLS::Callbacks::tls12_protocol_specific_kdf(std::string_view prf_algo) const {
   return TLS::CryptoOperations().tls12_protocol_specific_kdf(prf_algo);
}

void TLS::Callbacks::tls_session_established(const Session_Summary& session) {
   BOTAN_UNUSED(session);
}

std::vector<uint8_t> TLS::Callbacks::tls_provide_cert_status(const std::vector<X509_Certificate>& chain,
                                                             const Certificate_Status_Request& csr) {
   BOTAN_UNUSED(chain, csr);
   return std::vector<uint8_t>();
}

void TLS::Callbacks::tls_log_error(const char* err) {
   BOTAN_UNUSED(err);
}

void TLS::Callbacks::tls_log_debug(const char* what) {
   BOTAN_UNUSED(what);
}

void TLS::Callbacks::tls_log_debug_bin(const char* descr, const uint8_t val[], size_t val_len) {
   BOTAN_UNUSED(descr, val, val_len);
}

void TLS::Callbacks::tls_ssl_key_log_data(std::string_view label,
                                          std::span<const uint8_t> client_random,
                                          std::span<const uint8_t> secret) const {
   BOTAN_UNUSED(label, client_random, secret);
}

}  // namespace Botan
