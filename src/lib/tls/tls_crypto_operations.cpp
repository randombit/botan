/*
* TLS Cryptographic Operations
* (C) 2016,2026 Jack Lloyd
* (C) 2017 Harry Reimann, Rohde & Schwarz Cybersecurity
* (C) 2022,2023 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/aead.h>
#include <botan/block_cipher.h>
#include <botan/dh.h>
#include <botan/dl_group.h>
#include <botan/ec_group.h>
#include <botan/ecdh.h>
#include <botan/hash.h>
#include <botan/kdf.h>
#include <botan/mac.h>
#include <botan/ocsp.h>
#include <botan/pk_algs.h>
#if defined(BOTAN_HAS_PASSWORD_HASHING)
   #include <botan/pwdhash.h>
#endif
#include <botan/tls_algos.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_ciphersuite.h>
#include <botan/tls_crypto_operations.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>
#include <botan/tls_session.h>
#include <botan/tls_version.h>
#include <botan/x509_key.h>
#include <botan/x509path.h>
#include <botan/internal/fmt.h>
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

#if defined(BOTAN_HAS_TLS_CBC)
   #include <botan/internal/tls_cbc.h>
#endif

#if defined(BOTAN_HAS_TLS_NULL)
   #include <botan/internal/tls_null.h>
#endif

namespace Botan {

std::unique_ptr<HashFunction> TLS::CryptoOperations::create_hash(std::string_view algorithm) const {
   return HashFunction::create_or_throw(algorithm);
}

std::unique_ptr<MessageAuthenticationCode> TLS::CryptoOperations::create_mac(std::string_view algorithm) const {
   return MessageAuthenticationCode::create_or_throw(algorithm);
}

std::unique_ptr<KDF> TLS::CryptoOperations::create_kdf(std::string_view algorithm) const {
   return KDF::create_or_throw(algorithm);
}

std::unique_ptr<BlockCipher> TLS::CryptoOperations::create_block_cipher(std::string_view algorithm) const {
   return BlockCipher::create_or_throw(algorithm);
}

std::unique_ptr<PasswordHashFamily> TLS::CryptoOperations::create_password_hash_family(
   std::string_view algorithm) const {
#if defined(BOTAN_HAS_PASSWORD_HASHING)
   return PasswordHashFamily::create_or_throw(algorithm);
#else
   BOTAN_UNUSED(algorithm);
   throw Not_Implemented("Password hashing is not available in this build");
#endif
}

std::unique_ptr<AEAD_Mode> TLS::CryptoOperations::create_aead(std::string_view algorithm, Cipher_Dir direction) const {
   return AEAD_Mode::create_or_throw(algorithm, direction);
}

std::unique_ptr<AEAD_Mode> TLS::CryptoOperations::create_tls12_record_cipher(const TLS::Ciphersuite& suite,
                                                                             TLS::Protocol_Version version,
                                                                             Cipher_Dir direction,
                                                                             bool uses_encrypt_then_mac) const {
   if(suite.nonce_format() == TLS::Nonce_Format::CBC_MODE) {
#if defined(BOTAN_HAS_TLS_CBC)
      // legacy CBC+HMAC mode
      auto mac = create_mac(fmt("HMAC({})", suite.mac_algo()));
      auto cipher = create_block_cipher(suite.cipher_algo());

      if(direction == Cipher_Dir::Encryption) {
         return std::make_unique<TLS::TLS_CBC_HMAC_AEAD_Encryption>(std::move(cipher),
                                                                    std::move(mac),
                                                                    suite.cipher_keylen(),
                                                                    suite.mac_keylen(),
                                                                    version,
                                                                    uses_encrypt_then_mac);
      } else {
         return std::make_unique<TLS::TLS_CBC_HMAC_AEAD_Decryption>(std::move(cipher),
                                                                    std::move(mac),
                                                                    suite.cipher_keylen(),
                                                                    suite.mac_keylen(),
                                                                    version,
                                                                    uses_encrypt_then_mac);
      }

#else
      BOTAN_UNUSED(version, uses_encrypt_then_mac);
      throw Internal_Error("Negotiated disabled TLS CBC+HMAC ciphersuite");
#endif
   } else if(suite.nonce_format() == TLS::Nonce_Format::NULL_CIPHER) {
#if defined(BOTAN_HAS_TLS_NULL)
      auto mac = create_mac(fmt("HMAC({})", suite.mac_algo()));

      if(direction == Cipher_Dir::Encryption) {
         return std::make_unique<TLS::TLS_NULL_HMAC_AEAD_Encryption>(std::move(mac), suite.mac_keylen());
      } else {
         return std::make_unique<TLS::TLS_NULL_HMAC_AEAD_Decryption>(std::move(mac), suite.mac_keylen());
      }
#else
      throw Internal_Error("Negotiated disabled TLS NULL ciphersuite");
#endif
   } else {
      return create_aead(suite.cipher_algo(), direction);
   }
}

std::unique_ptr<Public_Key> TLS::CryptoOperations::load_public_key(
   std::span<const uint8_t> subject_public_key_info) const {
   return X509::load_key(subject_public_key_info);
}

std::unique_ptr<PK_Encryptor> TLS::CryptoOperations::create_rsa_encryptor(const Public_Key& key,
                                                                          RandomNumberGenerator& rng) {
   return std::make_unique<PK_Encryptor_EME>(key, rng, "PKCS1v15");
}

std::unique_ptr<PK_Decryptor> TLS::CryptoOperations::create_rsa_decryptor(const Private_Key& key,
                                                                          RandomNumberGenerator& rng) {
   return std::make_unique<PK_Decryptor_EME>(key, rng, "PKCS1v15");
}

std::vector<uint8_t> TLS::CryptoOperations::sign_message(const Private_Key& key,
                                                         RandomNumberGenerator& rng,
                                                         std::string_view padding,
                                                         Signature_Format format,
                                                         std::span<const uint8_t> msg) {
   PK_Signer signer(key, rng, padding, format);

   return signer.sign_message(msg, rng);
}

bool TLS::CryptoOperations::verify_message(const Public_Key& key,
                                           std::string_view padding,
                                           Signature_Format format,
                                           std::span<const uint8_t> msg,
                                           std::span<const uint8_t> sig) {
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
   return std::visit(overloaded{[](const DL_Group& dl_group) { return dl_group; },
                                [&](TLS::Group_Params group_param) {
                                   return DL_Group::from_name(group_param.to_algorithm_spec().value());
                                }},
                     group);
}

}  // namespace

std::unique_ptr<Public_Key> TLS::CryptoOperations::deserialize_peer_public_key(
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
      const auto ec_group = EC_Group::from_name(group_params.to_algorithm_spec().value());
      // TLS 1.3 requires uncompressed points (checked when parsing the key
      // share); TLS 1.2 may negotiate the compressed format. The deprecated
      // hybrid encoding and the identity element are never accepted.

      auto point = [&]() -> EC_AffinePoint {
         if(auto pt_uncompressed = EC_AffinePoint::deserialize_uncompressed(ec_group, key_bits)) {
            return std::move(pt_uncompressed).value();
         } else if(auto pt_compressed = EC_AffinePoint::deserialize_compressed(ec_group, key_bits)) {
            return std::move(pt_compressed).value();
         } else {
            throw Decoding_Error("Invalid ECDH public key encoding");
         }
      }();
      return std::make_unique<ECDH_PublicKey>(ec_group, std::move(point));
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
      return std::make_unique<ML_KEM_PublicKey>(key_bits, ML_KEM_Mode(group_params.to_algorithm_spec().value()));
   }
#endif

#if defined(BOTAN_HAS_FRODOKEM)
   if(group_params.is_pure_frodokem()) {
      return std::make_unique<FrodoKEM_PublicKey>(key_bits, FrodoKEMMode(group_params.to_algorithm_spec().value()));
   }
#endif

   throw Decoding_Error("cannot create a key offering without a group definition");
}

std::unique_ptr<Private_Key> TLS::CryptoOperations::kem_generate_key(TLS::Group_Params group,
                                                                     RandomNumberGenerator& rng) {
#if defined(BOTAN_HAS_ML_KEM)
   if(group.is_pure_ml_kem()) {
      return std::make_unique<ML_KEM_PrivateKey>(rng, ML_KEM_Mode(group.to_algorithm_spec().value()));
   }
#endif

#if defined(BOTAN_HAS_FRODOKEM)
   if(group.is_pure_frodokem()) {
      return std::make_unique<FrodoKEM_PrivateKey>(rng, FrodoKEMMode(group.to_algorithm_spec().value()));
   }
#endif

#if defined(BOTAN_HAS_TLS_13_PQC)
   if(group.is_pqc_hybrid()) {
      return Hybrid_KEM_PrivateKey::generate_from_group(group, rng);
   }
#endif

   return generate_ephemeral_key(group, rng);
}

KEM_Encapsulation TLS::CryptoOperations::kem_encapsulate(TLS::Group_Params group,
                                                         std::span<const uint8_t> encoded_public_key,
                                                         RandomNumberGenerator& rng,
                                                         const Policy& policy) {
   if(group.is_kem()) {
      auto kem_pub_key = [&] {
         try {
            return deserialize_peer_public_key(group, encoded_public_key);
         } catch(const Decoding_Error& ex) {
            // This exception means that the public key was invalid. However,
            // TLS' DecodeError would imply that a protocol message was invalid.
            throw TLS_Exception(Alert::IllegalParameter, ex.what());
         } catch(const Invalid_Argument& ex) {
            throw TLS_Exception(Alert::IllegalParameter, ex.what());
         }
      }();

      BOTAN_ASSERT_NONNULL(kem_pub_key);
      policy.check_peer_key_acceptable(*kem_pub_key);

      try {
         return PK_KEM_Encryptor(*kem_pub_key, "Raw").encrypt(rng);
      } catch(const Decoding_Error& ex) {
         throw TLS_Exception(Alert::IllegalParameter, ex.what());
      } catch(const Invalid_Argument& ex) {
         throw TLS_Exception(Alert::IllegalParameter, ex.what());
      }
   } else {
      // TODO: We could use the KEX_to_KEM_Adapter to remove the case distinction
      //       of KEM and KEX. However, the workarounds in this adapter class
      //       should first be addressed.
      auto ephemeral_keypair = generate_ephemeral_key(group, rng);
      BOTAN_ASSERT_NONNULL(ephemeral_keypair);
      return {ephemeral_keypair->public_value(),
              ephemeral_key_agreement(group, *ephemeral_keypair, encoded_public_key, rng, policy)};
   }
}

secure_vector<uint8_t> TLS::CryptoOperations::kem_decapsulate(TLS::Group_Params group,
                                                              const Private_Key& private_key,
                                                              std::span<const uint8_t> encapsulated_bytes,
                                                              RandomNumberGenerator& rng,
                                                              const Policy& policy) {
   if(group.is_kem()) {
      PK_KEM_Decryptor kemdec(private_key, rng, "Raw");
      if(encapsulated_bytes.size() != kemdec.encapsulated_key_length()) {
         throw TLS_Exception(Alert::IllegalParameter, "Invalid encapsulated key length");
      }
      try {
         return kemdec.decrypt(encapsulated_bytes, 0, {});
      } catch(const Decoding_Error& ex) {
         throw TLS_Exception(Alert::IllegalParameter, ex.what());
      } catch(const Invalid_Argument& ex) {
         throw TLS_Exception(Alert::IllegalParameter, ex.what());
      }
   }

   try {
      const auto& key_agreement_key = dynamic_cast<const PK_Key_Agreement_Key&>(private_key);
      return ephemeral_key_agreement(group, key_agreement_key, encapsulated_bytes, rng, policy);
   } catch(const std::bad_cast&) {
      throw Invalid_Argument("provided ephemeral key is not a PK_Key_Agreement_Key");
   }
}

std::unique_ptr<PK_Key_Agreement_Key> TLS::CryptoOperations::generate_ephemeral_key(
   const std::variant<TLS::Group_Params, DL_Group>& group, RandomNumberGenerator& rng) {
   if(is_dh_group(group)) {
      const DL_Group dl_group = get_dl_group(group);
      return std::make_unique<DH_PrivateKey>(rng, dl_group);
   }

   BOTAN_ASSERT_NOMSG(std::holds_alternative<TLS::Group_Params>(group));
   const auto group_params = std::get<TLS::Group_Params>(group);

   if(group_params.is_ecdh_named_curve()) {
      const auto ec_group = EC_Group::from_name(group_params.to_algorithm_spec().value());
      auto ecdh_key = std::make_unique<ECDH_PrivateKey>(rng, ec_group);

      // RFC 8446 Ch. 4.2.8.2
      //
      //   Note: Versions of TLS prior to 1.3 permitted point format
      //   negotiation; TLS 1.3 removes this feature in favor of a single point
      //   format for each curve.
      //
      // Hence, TLS 1.3 won't take Policy::use_ecc_point_compression() or
      // ClientHello::prefers_compressed_ec_points() into account but always use
      // uncompressed point encoding. Note that TLS 1.2 uses the
      // `tls12_generate_ephemeral_ecdh_key()` callback, which allows to specify
      // the point encoding format.
      ecdh_key->set_point_encoding(EC_Point_Format::Uncompressed);
      return ecdh_key;
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

std::unique_ptr<PK_Key_Agreement_Key> TLS::CryptoOperations::tls12_generate_ephemeral_ecdh_key(
   TLS::Group_Params group, RandomNumberGenerator& rng, EC_Point_Format tls12_ecc_pubkey_encoding_format) {
   // Delegating to the "universal" callback to obtain an ECDH key pair
   auto key = generate_ephemeral_key(group, rng);

   // For ordinary ECDH key pairs (that are derived from `ECDH_PublicKey`), we
   // set the internal point encoding flag for the key before passing it on into
   // the TLS 1.2 implementation. For user-defined keypair types (e.g. to
   // offload to some crypto hardware) inheriting from Botan's `ECDH_PublicKey`
   // might not be feasible. Such users should consider overriding this
   // ECDH-specific callback and ensure that their custom class handles the
   // public point encoding as requested by `tls12_ecc_pubkey_encoding_format`.
   if(auto* ecc_key = dynamic_cast<ECDH_PublicKey*>(key.get())) {
      ecc_key->set_point_encoding(tls12_ecc_pubkey_encoding_format);
   }

   return key;
}

secure_vector<uint8_t> TLS::CryptoOperations::ephemeral_key_agreement(
   const std::variant<TLS::Group_Params, DL_Group>& group,
   const PK_Key_Agreement_Key& private_key,
   std::span<const uint8_t> public_value,
   RandomNumberGenerator& rng,
   const Policy& policy) {
   const auto kex_pub_key = [&]() {
      try {
         return deserialize_peer_public_key(group, public_value);
      } catch(const Decoding_Error& ex) {
         // This exception means that the public key was invalid. However,
         // TLS' DecodeError would imply that a protocol message was invalid.
         throw TLS_Exception(Alert::IllegalParameter, ex.what());
      } catch(const Invalid_Argument& ex) {
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
      const PK_Key_Agreement ka(private_key, rng, "Raw");
      return ka.derive_key(0, kex_pub_key->raw_public_key_bits()).bits_of();
   } catch(const Invalid_Argument& ex) {
      throw TLS_Exception(Alert::IllegalParameter, ex.what());
   }
}

std::unique_ptr<KDF> TLS::CryptoOperations::tls12_protocol_specific_kdf(std::string_view prf_algo) const {
   if(prf_algo == "MD5" || prf_algo == "SHA-1") {
      return create_kdf("TLS-12-PRF(SHA-256)");
   }

   return create_kdf(Botan::fmt("TLS-12-PRF({})", prf_algo));
}

std::vector<uint8_t> TLS::DefaultCryptoOperations::sign_message(const Private_Key& key,
                                                                RandomNumberGenerator& rng,
                                                                std::string_view padding,
                                                                Signature_Format format,
                                                                std::span<const uint8_t> msg) {
   return m_callbacks.tls_sign_message(key, rng, padding, format, std::vector<uint8_t>(msg.begin(), msg.end()));
}

bool TLS::DefaultCryptoOperations::verify_message(const Public_Key& key,
                                                  std::string_view padding,
                                                  Signature_Format format,
                                                  std::span<const uint8_t> msg,
                                                  std::span<const uint8_t> sig) {
   return m_callbacks.tls_verify_message(
      key, padding, format, std::vector<uint8_t>(msg.begin(), msg.end()), std::vector<uint8_t>(sig.begin(), sig.end()));
}

std::unique_ptr<Public_Key> TLS::DefaultCryptoOperations::deserialize_peer_public_key(
   const std::variant<TLS::Group_Params, DL_Group>& group, std::span<const uint8_t> key_bits) {
   return m_callbacks.tls_deserialize_peer_public_key(group, key_bits);
}

std::unique_ptr<Private_Key> TLS::DefaultCryptoOperations::kem_generate_key(TLS::Group_Params group,
                                                                            RandomNumberGenerator& rng) {
   return m_callbacks.tls_kem_generate_key(group, rng);
}

KEM_Encapsulation TLS::DefaultCryptoOperations::kem_encapsulate(TLS::Group_Params group,
                                                                std::span<const uint8_t> encoded_public_key,
                                                                RandomNumberGenerator& rng,
                                                                const Policy& policy) {
   return m_callbacks.tls_kem_encapsulate(
      group, std::vector<uint8_t>(encoded_public_key.begin(), encoded_public_key.end()), rng, policy);
}

secure_vector<uint8_t> TLS::DefaultCryptoOperations::kem_decapsulate(TLS::Group_Params group,
                                                                     const Private_Key& private_key,
                                                                     std::span<const uint8_t> encapsulated_bytes,
                                                                     RandomNumberGenerator& rng,
                                                                     const Policy& policy) {
   return m_callbacks.tls_kem_decapsulate(
      group, private_key, std::vector<uint8_t>(encapsulated_bytes.begin(), encapsulated_bytes.end()), rng, policy);
}

std::unique_ptr<PK_Key_Agreement_Key> TLS::DefaultCryptoOperations::generate_ephemeral_key(
   const std::variant<TLS::Group_Params, DL_Group>& group, RandomNumberGenerator& rng) {
   return m_callbacks.tls_generate_ephemeral_key(group, rng);
}

std::unique_ptr<PK_Key_Agreement_Key> TLS::DefaultCryptoOperations::tls12_generate_ephemeral_ecdh_key(
   TLS::Group_Params group, RandomNumberGenerator& rng, EC_Point_Format tls12_ecc_pubkey_encoding_format) {
   return m_callbacks.tls12_generate_ephemeral_ecdh_key(group, rng, tls12_ecc_pubkey_encoding_format);
}

secure_vector<uint8_t> TLS::DefaultCryptoOperations::ephemeral_key_agreement(
   const std::variant<TLS::Group_Params, DL_Group>& group,
   const PK_Key_Agreement_Key& private_key,
   std::span<const uint8_t> public_value,
   RandomNumberGenerator& rng,
   const Policy& policy) {
   return m_callbacks.tls_ephemeral_key_agreement(
      group, private_key, std::vector<uint8_t>(public_value.begin(), public_value.end()), rng, policy);
}

std::unique_ptr<KDF> TLS::DefaultCryptoOperations::tls12_protocol_specific_kdf(std::string_view prf_algo) const {
   return m_callbacks.tls12_protocol_specific_kdf(prf_algo);
}

}  // namespace Botan
