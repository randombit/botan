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

#include <botan/dh.h>
#include <botan/dl_group.h>
#include <botan/ecdh.h>
#include <botan/ocsp.h>
#include <botan/pk_algs.h>
#include <botan/tls_algos.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>
#include <botan/x509path.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/stl_util.h>

#if defined(BOTAN_HAS_X25519)
   #include <botan/x25519.h>
#endif

#if defined(BOTAN_HAS_X448)
   #include <botan/x448.h>
#endif

#if defined(BOTAN_HAS_ML_KEM)
   #include <botan/ml_kem.h>
#endif

#if defined(BOTAN_HAS_FRODOKEM)
   #include <botan/frodokem.h>
#endif

#if defined(BOTAN_HAS_TLS_13_PQC)
   #include <botan/internal/hybrid_public_key.h>
#endif

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

   Path_Validation_Restrictions restrictions(policy.require_cert_revocation_info(),
                                             policy.minimum_signature_strength());

   Path_Validation_Result result = x509_path_validate(cert_chain,
                                                      restrictions,
                                                      trusted_roots,
                                                      hostname,
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
   PK_Signer signer(key, rng, padding, format);

   return signer.sign_message(msg, rng);
}

bool TLS::Callbacks::tls_verify_message(const Public_Key& key,
                                        std::string_view padding,
                                        Signature_Format format,
                                        const std::vector<uint8_t>& msg,
                                        const std::vector<uint8_t>& sig) {
   PK_Verifier verifier(key, padding, format);

   return verifier.verify_message(msg, sig);
}

namespace {

bool is_dh_group(const std::variant<TLS::Group_Params, DL_Group>& group) {
   return std::holds_alternative<DL_Group>(group) || std::get<TLS::Group_Params>(group).is_dh_named_group();
}

DL_Group get_dl_group(const std::variant<TLS::Group_Params, DL_Group>& group) {
   BOTAN_ASSERT_NOMSG(is_dh_group(group));

   // TLS 1.2 allows specifying arbitrary DL_Group parameters in-lieu of
   // a standardized DH group identifier. TLS 1.3 just offers pre-defined
   // groups.
   return std::visit(
      overloaded{[](const DL_Group& dl_group) { return dl_group; },
                 [&](TLS::Group_Params group_param) { return DL_Group::from_name(group_param.to_string().value()); }},
      group);
}

}  // namespace

std::unique_ptr<Public_Key> TLS::Callbacks::tls_deserialize_peer_public_key(
   const std::variant<TLS::Group_Params, DL_Group>& group, std::span<const uint8_t> key_bits) {
   if(is_dh_group(group)) {
      // TLS 1.2 allows specifying arbitrary DL_Group parameters in-lieu of
      // a standardized DH group identifier.
      const auto dl_group = get_dl_group(group);

      auto Y = BigInt::from_bytes(key_bits);

      /*
       * A basic check for key validity. As we do not know q here we
       * cannot check that Y is in the right subgroup. However since
       * our key is ephemeral there does not seem to be any
       * advantage to bogus keys anyway.
       */
      if(Y <= 1 || Y >= dl_group.get_p() - 1) {
         throw Decoding_Error("Server sent bad DH key for DHE exchange");
      }

      return std::make_unique<DH_PublicKey>(dl_group, Y);
   }

   // The special case for TLS 1.2 with an explicit DH group definition is
   // handled above. All other cases are based on the opaque group definition.
   BOTAN_ASSERT_NOMSG(std::holds_alternative<TLS::Group_Params>(group));
   const auto group_params = std::get<TLS::Group_Params>(group);

   if(group_params.is_ecdh_named_curve()) {
      const auto ec_group = EC_Group::from_name(group_params.to_string().value());
      return std::make_unique<ECDH_PublicKey>(ec_group, EC_AffinePoint(ec_group, key_bits));
   }

#if defined(BOTAN_HAS_X25519)
   if(group_params.is_x25519()) {
      return std::make_unique<X25519_PublicKey>(key_bits);
   }
#endif

#if defined(BOTAN_HAS_X448)
   if(group_params.is_x448()) {
      return std::make_unique<X448_PublicKey>(key_bits);
   }
#endif

#if defined(BOTAN_HAS_TLS_13_PQC)
   if(group_params.is_pqc_hybrid()) {
      return Hybrid_KEM_PublicKey::load_for_group(group_params, key_bits);
   }
#endif

#if defined(BOTAN_HAS_ML_KEM)
   if(group_params.is_pure_ml_kem()) {
      return std::make_unique<ML_KEM_PublicKey>(key_bits, ML_KEM_Mode(group_params.to_string().value()));
   }
#endif

#if defined(BOTAN_HAS_FRODOKEM)
   if(group_params.is_pure_frodokem()) {
      return std::make_unique<FrodoKEM_PublicKey>(key_bits, FrodoKEMMode(group_params.to_string().value()));
   }
#endif

   throw Decoding_Error("cannot create a key offering without a group definition");
}

std::unique_ptr<Private_Key> TLS::Callbacks::tls_kem_generate_key(TLS::Group_Params group, RandomNumberGenerator& rng) {
#if defined(BOTAN_HAS_ML_KEM)
   if(group.is_pure_ml_kem()) {
      return std::make_unique<ML_KEM_PrivateKey>(rng, ML_KEM_Mode(group.to_string().value()));
   }
#endif

#if defined(BOTAN_HAS_FRODOKEM)
   if(group.is_pure_frodokem()) {
      return std::make_unique<FrodoKEM_PrivateKey>(rng, FrodoKEMMode(group.to_string().value()));
   }
#endif

#if defined(BOTAN_HAS_TLS_13_PQC)
   if(group.is_pqc_hybrid()) {
      return Hybrid_KEM_PrivateKey::generate_from_group(group, rng);
   }
#endif

   return tls_generate_ephemeral_key(group, rng);
}

KEM_Encapsulation TLS::Callbacks::tls_kem_encapsulate(TLS::Group_Params group,
                                                      const std::vector<uint8_t>& encoded_public_key,
                                                      RandomNumberGenerator& rng,
                                                      const Policy& policy) {
   if(group.is_kem()) {
      auto kem_pub_key = [&] {
         try {
            return tls_deserialize_peer_public_key(group, encoded_public_key);
         } catch(const Decoding_Error& ex) {
            // This exception means that the public key was invalid. However,
            // TLS' DecodeError would imply that a protocol message was invalid.
            throw TLS_Exception(Alert::IllegalParameter, ex.what());
         }
      }();

      BOTAN_ASSERT_NONNULL(kem_pub_key);
      policy.check_peer_key_acceptable(*kem_pub_key);

      try {
         return PK_KEM_Encryptor(*kem_pub_key, "Raw").encrypt(rng);
      } catch(const Invalid_Argument& ex) {
         throw TLS_Exception(Alert::IllegalParameter, ex.what());
      }
   } else {
      // TODO: We could use the KEX_to_KEM_Adapter to remove the case distinction
      //       of KEM and KEX. However, the workarounds in this adapter class
      //       should first be addressed.
      auto ephemeral_keypair = tls_generate_ephemeral_key(group, rng);
      BOTAN_ASSERT_NONNULL(ephemeral_keypair);
      return {ephemeral_keypair->public_value(),
              tls_ephemeral_key_agreement(group, *ephemeral_keypair, encoded_public_key, rng, policy)};
   }
}

secure_vector<uint8_t> TLS::Callbacks::tls_kem_decapsulate(TLS::Group_Params group,
                                                           const Private_Key& private_key,
                                                           const std::vector<uint8_t>& encapsulated_bytes,
                                                           RandomNumberGenerator& rng,
                                                           const Policy& policy) {
   if(group.is_kem()) {
      PK_KEM_Decryptor kemdec(private_key, rng, "Raw");
      if(encapsulated_bytes.size() != kemdec.encapsulated_key_length()) {
         throw TLS_Exception(Alert::IllegalParameter, "Invalid encapsulated key length");
      }
      return kemdec.decrypt(encapsulated_bytes, 0, {});
   }

   try {
      auto& key_agreement_key = dynamic_cast<const PK_Key_Agreement_Key&>(private_key);
      return tls_ephemeral_key_agreement(group, key_agreement_key, encapsulated_bytes, rng, policy);
   } catch(const std::bad_cast&) {
      throw Invalid_Argument("provided ephemeral key is not a PK_Key_Agreement_Key");
   }
}

std::unique_ptr<PK_Key_Agreement_Key> TLS::Callbacks::tls_generate_ephemeral_key(
   const std::variant<TLS::Group_Params, DL_Group>& group, RandomNumberGenerator& rng) {
   if(is_dh_group(group)) {
      const DL_Group dl_group = get_dl_group(group);
      return std::make_unique<DH_PrivateKey>(rng, dl_group);
   }

   BOTAN_ASSERT_NOMSG(std::holds_alternative<TLS::Group_Params>(group));
   const auto group_params = std::get<TLS::Group_Params>(group);

   if(group_params.is_ecdh_named_curve()) {
      const auto ec_group = EC_Group::from_name(group_params.to_string().value());
      return std::make_unique<ECDH_PrivateKey>(rng, ec_group);
   }

#if defined(BOTAN_HAS_X25519)
   if(group_params.is_x25519()) {
      return std::make_unique<X25519_PrivateKey>(rng);
   }
#endif

#if defined(BOTAN_HAS_X448)
   if(group_params.is_x448()) {
      return std::make_unique<X448_PrivateKey>(rng);
   }
#endif

   if(group_params.is_kem()) {
      throw TLS_Exception(Alert::IllegalParameter, "cannot generate an ephemeral KEX key for a KEM");
   }

   throw TLS_Exception(Alert::DecodeError, "cannot create a key offering without a group definition");
}

secure_vector<uint8_t> TLS::Callbacks::tls_ephemeral_key_agreement(
   const std::variant<TLS::Group_Params, DL_Group>& group,
   const PK_Key_Agreement_Key& private_key,
   const std::vector<uint8_t>& public_value,
   RandomNumberGenerator& rng,
   const Policy& policy) {
   const auto kex_pub_key = [&]() {
      try {
         return tls_deserialize_peer_public_key(group, public_value);
      } catch(const Decoding_Error& ex) {
         // This exception means that the public key was invalid. However,
         // TLS' DecodeError would imply that a protocol message was invalid.
         throw TLS_Exception(Alert::IllegalParameter, ex.what());
      }
   }();

   BOTAN_ASSERT_NONNULL(kex_pub_key);
   policy.check_peer_key_acceptable(*kex_pub_key);

   // RFC 8422 - 5.11.
   //   With X25519 and X448, a receiving party MUST check whether the
   //   computed premaster secret is the all-zero value and abort the
   //   handshake if so, as described in Section 6 of [RFC7748].
   //
   // This is done within the key agreement operation and throws
   // an Invalid_Argument exception if the shared secret is all-zero.
   try {
      PK_Key_Agreement ka(private_key, rng, "Raw");
      return ka.derive_key(0, kex_pub_key->raw_public_key_bits()).bits_of();
   } catch(const Invalid_Argument& ex) {
      throw TLS_Exception(Alert::IllegalParameter, ex.what());
   }
}

}  // namespace Botan
