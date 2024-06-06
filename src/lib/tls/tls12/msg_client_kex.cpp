/*
* Client Key Exchange Message
* (C) 2004-2010,2016 Jack Lloyd
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>

#include <botan/rng.h>
#include <botan/tls_extensions.h>

#include <botan/credentials_manager.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_reader.h>

#include <botan/ecdh.h>
#include <botan/rsa.h>

namespace Botan::TLS {

/*
* Create a new Client Key Exchange message
*/
Client_Key_Exchange::Client_Key_Exchange(Handshake_IO& io,
                                         Handshake_State& state,
                                         const Policy& policy,
                                         Credentials_Manager& creds,
                                         const Public_Key* server_public_key,
                                         std::string_view hostname,
                                         RandomNumberGenerator& rng) {
   const Kex_Algo kex_algo = state.ciphersuite().kex_method();

   if(kex_algo == Kex_Algo::PSK) {
      std::string identity_hint;

      if(state.server_kex()) {
         TLS_Data_Reader reader("ClientKeyExchange", state.server_kex()->params());
         identity_hint = reader.get_string(2, 0, 65535);
      }

      m_psk_identity = creds.psk_identity("tls-client", std::string(hostname), identity_hint);

      append_tls_length_value(m_key_material, to_byte_vector(m_psk_identity.value()), 2);

      SymmetricKey psk = creds.psk("tls-client", std::string(hostname), m_psk_identity.value());

      std::vector<uint8_t> zeros(psk.length());

      append_tls_length_value(m_pre_master, zeros, 2);
      append_tls_length_value(m_pre_master, psk.bits_of(), 2);
   } else if(state.server_kex()) {
      TLS_Data_Reader reader("ClientKeyExchange", state.server_kex()->params());

      SymmetricKey psk;

      if(kex_algo == Kex_Algo::ECDHE_PSK) {
         std::string identity_hint = reader.get_string(2, 0, 65535);

         m_psk_identity = creds.psk_identity("tls-client", std::string(hostname), identity_hint);

         append_tls_length_value(m_key_material, to_byte_vector(m_psk_identity.value()), 2);

         psk = creds.psk("tls-client", std::string(hostname), m_psk_identity.value());
      }

      if(kex_algo == Kex_Algo::DH) {
         const auto modulus = BigInt::from_bytes(reader.get_range<uint8_t>(2, 1, 65535));
         const auto generator = BigInt::from_bytes(reader.get_range<uint8_t>(2, 1, 65535));
         const std::vector<uint8_t> peer_public_value = reader.get_range<uint8_t>(2, 1, 65535);

         if(reader.remaining_bytes()) {
            throw Decoding_Error("Bad params size for DH key exchange");
         }

         DL_Group group(modulus, generator);

         if(!group.verify_group(rng, false)) {
            throw TLS_Exception(Alert::InsufficientSecurity, "DH group validation failed");
         }

         const auto private_key = state.callbacks().tls_generate_ephemeral_key(group, rng);
         auto shared_secret = CT::strip_leading_zeros(
            state.callbacks().tls_ephemeral_key_agreement(group, *private_key, peer_public_value, rng, policy));

         if(kex_algo == Kex_Algo::DH) {
            m_pre_master = std::move(shared_secret);
         } else {
            append_tls_length_value(m_pre_master, shared_secret, 2);
            append_tls_length_value(m_pre_master, psk.bits_of(), 2);
         }

         append_tls_length_value(m_key_material, private_key->public_value(), 2);
      } else if(kex_algo == Kex_Algo::ECDH || kex_algo == Kex_Algo::ECDHE_PSK) {
         const uint8_t curve_type = reader.get_byte();
         if(curve_type != 3) {
            throw Decoding_Error("Server sent non-named ECC curve");
         }

         const Group_Params curve_id = static_cast<Group_Params>(reader.get_uint16_t());
         const std::vector<uint8_t> peer_public_value = reader.get_range<uint8_t>(1, 1, 255);

         if(!curve_id.is_ecdh_named_curve() && !curve_id.is_x25519() && !curve_id.is_x448()) {
            throw TLS_Exception(Alert::HandshakeFailure,
                                "Server selected a group that is not compatible with the negotiated ciphersuite");
         }

         if(policy.choose_key_exchange_group({curve_id}, {}) != curve_id) {
            throw TLS_Exception(Alert::HandshakeFailure, "Server sent ECC curve prohibited by policy");
         }

         const auto private_key = state.callbacks().tls_generate_ephemeral_key(curve_id, rng);
         auto shared_secret =
            state.callbacks().tls_ephemeral_key_agreement(curve_id, *private_key, peer_public_value, rng, policy);

         // RFC 8422 - 5.11.
         //   With X25519 and X448, a receiving party MUST check whether the
         //   computed premaster secret is the all-zero value and abort the
         //   handshake if so, as described in Section 6 of [RFC7748].
         if((curve_id == Group_Params::X25519 || curve_id == Group_Params::X448) &&
            CT::all_zeros(shared_secret.data(), shared_secret.size()).as_bool()) {
            throw TLS_Exception(Alert::DecryptError, "Bad X25519 or X448 key exchange");
         }

         if(kex_algo == Kex_Algo::ECDH) {
            m_pre_master = std::move(shared_secret);
         } else {
            append_tls_length_value(m_pre_master, shared_secret, 2);
            append_tls_length_value(m_pre_master, psk.bits_of(), 2);
         }

         if(curve_id.is_ecdh_named_curve()) {
            auto ecdh_key = dynamic_cast<ECDH_PublicKey*>(private_key.get());
            if(!ecdh_key) {
               throw TLS_Exception(Alert::InternalError, "Application did not provide a ECDH_PublicKey");
            }
            append_tls_length_value(m_key_material,
                                    ecdh_key->public_value(state.server_hello()->prefers_compressed_ec_points()
                                                              ? EC_Point_Format::Compressed
                                                              : EC_Point_Format::Uncompressed),
                                    1);
         } else {
            append_tls_length_value(m_key_material, private_key->public_value(), 1);
         }
      } else {
         throw Internal_Error("Client_Key_Exchange: Unknown key exchange method was negotiated");
      }

      reader.assert_done();
   } else {
      // No server key exchange msg better mean RSA kex + RSA key in cert

      if(kex_algo != Kex_Algo::STATIC_RSA) {
         throw Unexpected_Message("No server kex message, but negotiated a key exchange that required it");
      }

      if(!server_public_key) {
         throw Internal_Error("No server public key for RSA exchange");
      }

      if(auto rsa_pub = dynamic_cast<const RSA_PublicKey*>(server_public_key)) {
         const Protocol_Version offered_version = state.client_hello()->legacy_version();

         rng.random_vec(m_pre_master, 48);
         m_pre_master[0] = offered_version.major_version();
         m_pre_master[1] = offered_version.minor_version();

         PK_Encryptor_EME encryptor(*rsa_pub, rng, "PKCS1v15");

         const std::vector<uint8_t> encrypted_key = encryptor.encrypt(m_pre_master, rng);

         append_tls_length_value(m_key_material, encrypted_key, 2);
      } else {
         throw TLS_Exception(Alert::HandshakeFailure,
                             "Expected a RSA key in server cert but got " + server_public_key->algo_name());
      }
   }

   state.hash().update(io.send(*this));
}

/*
* Read a Client Key Exchange message
*/
Client_Key_Exchange::Client_Key_Exchange(const std::vector<uint8_t>& contents,
                                         const Handshake_State& state,
                                         const Private_Key* server_rsa_kex_key,
                                         Credentials_Manager& creds,
                                         const Policy& policy,
                                         RandomNumberGenerator& rng) {
   const Kex_Algo kex_algo = state.ciphersuite().kex_method();

   if(kex_algo == Kex_Algo::STATIC_RSA) {
      BOTAN_ASSERT(state.server_certs() && !state.server_certs()->cert_chain().empty(),
                   "RSA key exchange negotiated so server sent a certificate");

      if(!server_rsa_kex_key) {
         throw Internal_Error("Expected RSA kex but no server kex key set");
      }

      if(server_rsa_kex_key->algo_name() != "RSA") {
         throw Internal_Error("Expected RSA key but got " + server_rsa_kex_key->algo_name());
      }

      TLS_Data_Reader reader("ClientKeyExchange", contents);
      const std::vector<uint8_t> encrypted_pre_master = reader.get_range<uint8_t>(2, 0, 65535);
      reader.assert_done();

      PK_Decryptor_EME decryptor(*server_rsa_kex_key, rng, "PKCS1v15");

      const uint8_t client_major = state.client_hello()->legacy_version().major_version();
      const uint8_t client_minor = state.client_hello()->legacy_version().minor_version();

      /*
      * PK_Decryptor::decrypt_or_random will return a random value if
      * either the length does not match the expected value or if the
      * version number embedded in the PMS does not match the one sent
      * in the client hello.
      */
      const size_t expected_plaintext_size = 48;
      const size_t expected_content_size = 2;
      const uint8_t expected_content_bytes[expected_content_size] = {client_major, client_minor};
      const uint8_t expected_content_pos[expected_content_size] = {0, 1};

      m_pre_master = decryptor.decrypt_or_random(encrypted_pre_master.data(),
                                                 encrypted_pre_master.size(),
                                                 expected_plaintext_size,
                                                 rng,
                                                 expected_content_bytes,
                                                 expected_content_pos,
                                                 expected_content_size);
   } else {
      TLS_Data_Reader reader("ClientKeyExchange", contents);

      SymmetricKey psk;

      if(key_exchange_is_psk(kex_algo)) {
         m_psk_identity = reader.get_string(2, 0, 65535);

         psk = creds.psk("tls-server", state.client_hello()->sni_hostname(), m_psk_identity.value());

         if(psk.empty()) {
            if(policy.hide_unknown_users()) {
               psk = SymmetricKey(rng, 16);
            } else {
               throw TLS_Exception(Alert::UnknownPSKIdentity, "No PSK for identifier " + m_psk_identity.value());
            }
         }
      }

      if(kex_algo == Kex_Algo::PSK) {
         std::vector<uint8_t> zeros(psk.length());
         append_tls_length_value(m_pre_master, zeros, 2);
         append_tls_length_value(m_pre_master, psk.bits_of(), 2);
      } else if(kex_algo == Kex_Algo::DH || kex_algo == Kex_Algo::ECDH || kex_algo == Kex_Algo::ECDHE_PSK) {
         const PK_Key_Agreement_Key& ka_key = state.server_kex()->server_kex_key();

         const std::vector<uint8_t> client_pubkey = (ka_key.algo_name() == "DH")
                                                       ? reader.get_range<uint8_t>(2, 0, 65535)
                                                       : reader.get_range<uint8_t>(1, 1, 255);

         const auto shared_group = state.server_kex()->shared_group();
         BOTAN_STATE_CHECK(shared_group && shared_group.value() != Group_Params::NONE);

         try {
            auto shared_secret =
               state.callbacks().tls_ephemeral_key_agreement(shared_group.value(), ka_key, client_pubkey, rng, policy);

            if(ka_key.algo_name() == "DH") {
               shared_secret = CT::strip_leading_zeros(shared_secret);
            }

            if(kex_algo == Kex_Algo::ECDH || kex_algo == Kex_Algo::ECDHE_PSK) {
               // RFC 8422 - 5.11.
               //   With X25519 and X448, a receiving party MUST check whether the
               //   computed premaster secret is the all-zero value and abort the
               //   handshake if so, as described in Section 6 of [RFC7748].
               BOTAN_ASSERT_NOMSG(state.server_kex()->params().size() >= 3);
               Group_Params group = static_cast<Group_Params>(state.server_kex()->params().at(2));
               if((group == Group_Params::X25519 || group == Group_Params::X448) &&
                  CT::all_zeros(shared_secret.data(), shared_secret.size()).as_bool()) {
                  throw TLS_Exception(Alert::DecryptError, "Bad X25519 or X448 key exchange");
               }
            }

            if(kex_algo == Kex_Algo::ECDHE_PSK) {
               append_tls_length_value(m_pre_master, shared_secret, 2);
               append_tls_length_value(m_pre_master, psk.bits_of(), 2);
            } else {
               m_pre_master = shared_secret;
            }
         } catch(Invalid_Argument& e) {
            throw TLS_Exception(Alert::IllegalParameter, e.what());
         } catch(TLS_Exception& e) {
            // NOLINTNEXTLINE(cert-err60-cpp)
            throw e;
         } catch(std::exception&) {
            /*
            * Something failed in the DH/ECDH computation. To avoid possible
            * attacks which are based on triggering and detecting some edge
            * failure condition, randomize the pre-master output and carry on,
            * allowing the protocol to fail later in the finished checks.
            */
            rng.random_vec(m_pre_master, ka_key.public_value().size());
         }

         reader.assert_done();
      } else {
         throw Internal_Error("Client_Key_Exchange: Unknown key exchange negotiated");
      }
   }
}

}  // namespace Botan::TLS
