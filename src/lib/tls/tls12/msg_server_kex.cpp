/*
* Server Key Exchange Message
* (C) 2004-2010,2012,2015,2016 Jack Lloyd
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>

#include <botan/credentials_manager.h>
#include <botan/pubkey.h>
#include <botan/tls_extensions.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_reader.h>

#include <botan/dh.h>
#include <botan/dl_group.h>
#include <botan/ecdh.h>

#if defined(BOTAN_HAS_X25519)
   #include <botan/x25519.h>
#endif
#if defined(BOTAN_HAS_X448)
   #include <botan/x448.h>
#endif

namespace Botan::TLS {

/**
* Create a new Server Key Exchange message
*/
Server_Key_Exchange::Server_Key_Exchange(Handshake_IO& io,
                                         Handshake_State& state,
                                         const Policy& policy,
                                         Credentials_Manager& creds,
                                         RandomNumberGenerator& rng,
                                         const Private_Key* signing_key) {
   const std::string hostname = state.client_hello()->sni_hostname();
   const Kex_Algo kex_algo = state.ciphersuite().kex_method();

   if(kex_algo == Kex_Algo::PSK || kex_algo == Kex_Algo::ECDHE_PSK) {
      std::string identity_hint = creds.psk_identity_hint("tls-server", hostname);

      append_tls_length_value(m_params, identity_hint, 2);
   }

   if(kex_algo == Kex_Algo::DH) {
      const std::vector<Group_Params> dh_groups = state.client_hello()->supported_dh_groups();

      m_shared_group = Group_Params::NONE;

      /*
      RFC 7919 requires that if the client sends any groups in the FFDHE
      range, that we must select one of these. If this is not possible,
      then we are required to reject the connection.

      If the client did not send any DH groups, but did offer DH ciphersuites
      and we selected one, then consult the policy for which DH group to pick.
      */

      if(dh_groups.empty()) {
         m_shared_group = policy.default_dh_group();
      } else {
         m_shared_group = policy.choose_key_exchange_group(dh_groups, {});
      }

      if(m_shared_group.value() == Group_Params::NONE) {
         throw TLS_Exception(Alert::HandshakeFailure, "Could not agree on a DH group with the client");
      }

      // The policy had better return a group we know about:
      BOTAN_ASSERT(m_shared_group.value().is_dh_named_group(), "DH ciphersuite is using a known finite field group");

      // Note: TLS 1.2 allows defining and using arbitrary DH groups (additional
      //       to the named and standardized ones). This API doesn't allow the
      //       server to make use of that at the moment. TLS 1.3 does not
      //       provide this flexibility!
      //
      // A possible implementation strategy in case one would ever need that:
      // `Policy::default_dh_group()` could return a `std::variant<Group_Params,
      // DL_Group>`, allowing it to define arbitrary groups.
      m_kex_key = state.callbacks().tls_generate_ephemeral_key(m_shared_group.value(), rng);
      auto dh = dynamic_cast<DH_PrivateKey*>(m_kex_key.get());
      if(!dh) {
         throw TLS_Exception(Alert::InternalError, "Application did not provide a Diffie-Hellman key");
      }

      append_tls_length_value(m_params, dh->get_int_field("p").serialize(), 2);
      append_tls_length_value(m_params, dh->get_int_field("g").serialize(), 2);
      append_tls_length_value(m_params, dh->public_value(), 2);
   } else if(kex_algo == Kex_Algo::ECDH || kex_algo == Kex_Algo::ECDHE_PSK) {
      const std::vector<Group_Params> ec_groups = state.client_hello()->supported_ecc_curves();

      if(ec_groups.empty()) {
         throw Internal_Error("Client sent no ECC extension but we negotiated ECDH");
      }

      m_shared_group = policy.choose_key_exchange_group(ec_groups, {});

      if(m_shared_group.value() == Group_Params::NONE) {
         throw TLS_Exception(Alert::HandshakeFailure, "No shared ECC group with client");
      }

      std::vector<uint8_t> ecdh_public_val;

      if(m_shared_group.value() == Group_Params::X25519 || m_shared_group.value() == Group_Params::X448) {
         m_kex_key = state.callbacks().tls_generate_ephemeral_key(m_shared_group.value(), rng);
         if(!m_kex_key) {
            throw TLS_Exception(Alert::InternalError, "Application did not provide an EC key");
         }
         ecdh_public_val = m_kex_key->public_value();
      } else {
         m_kex_key = state.callbacks().tls_generate_ephemeral_key(m_shared_group.value(), rng);
         auto ecdh = dynamic_cast<ECDH_PrivateKey*>(m_kex_key.get());
         if(!ecdh) {
            throw TLS_Exception(Alert::InternalError, "Application did not provide a EC-Diffie-Hellman key");
         }

         // follow client's preference for point compression
         ecdh_public_val =
            ecdh->public_value(state.client_hello()->prefers_compressed_ec_points() ? EC_Point_Format::Compressed
                                                                                    : EC_Point_Format::Uncompressed);
      }

      const uint16_t named_curve_id = m_shared_group.value().wire_code();
      m_params.push_back(3);  // named curve
      m_params.push_back(get_byte<0>(named_curve_id));
      m_params.push_back(get_byte<1>(named_curve_id));

      append_tls_length_value(m_params, ecdh_public_val, 1);
   } else if(kex_algo != Kex_Algo::PSK) {
      throw Internal_Error("Server_Key_Exchange: Unknown kex type " + kex_method_to_string(kex_algo));
   }

   if(state.ciphersuite().signature_used()) {
      BOTAN_ASSERT(signing_key, "Signing key was set");

      std::pair<std::string, Signature_Format> format = state.choose_sig_format(*signing_key, m_scheme, false, policy);

      std::vector<uint8_t> buf = state.client_hello()->random();

      buf += state.server_hello()->random();
      buf += params();

      m_signature = state.callbacks().tls_sign_message(*signing_key, rng, format.first, format.second, buf);
   }

   state.hash().update(io.send(*this));
}

/**
* Deserialize a Server Key Exchange message
*/
Server_Key_Exchange::Server_Key_Exchange(const std::vector<uint8_t>& buf,
                                         const Kex_Algo kex_algo,
                                         const Auth_Method auth_method,
                                         Protocol_Version version) {
   BOTAN_UNUSED(version);  // remove this
   TLS_Data_Reader reader("ServerKeyExchange", buf);

   /*
   * Here we are deserializing enough to find out what offset the
   * signature is at. All processing is done when the Client Key Exchange
   * is prepared.
   */

   if(kex_algo == Kex_Algo::PSK || kex_algo == Kex_Algo::ECDHE_PSK) {
      reader.get_string(2, 0, 65535);  // identity hint
   }

   if(kex_algo == Kex_Algo::DH) {
      // 3 bigints, DH p, g, Y

      for(size_t i = 0; i != 3; ++i) {
         reader.get_range<uint8_t>(2, 1, 65535);
      }
   } else if(kex_algo == Kex_Algo::ECDH || kex_algo == Kex_Algo::ECDHE_PSK) {
      reader.get_byte();                     // curve type
      reader.get_uint16_t();                 // curve id
      reader.get_range<uint8_t>(1, 1, 255);  // public key
   } else if(kex_algo != Kex_Algo::PSK) {
      throw Decoding_Error("Server_Key_Exchange: Unsupported kex type " + kex_method_to_string(kex_algo));
   }

   m_params.assign(buf.data(), buf.data() + reader.read_so_far());

   if(auth_method != Auth_Method::IMPLICIT) {
      m_scheme = Signature_Scheme(reader.get_uint16_t());
      m_signature = reader.get_range<uint8_t>(2, 0, 65535);
   }

   reader.assert_done();
}

/**
* Serialize a Server Key Exchange message
*/
std::vector<uint8_t> Server_Key_Exchange::serialize() const {
   std::vector<uint8_t> buf = params();

   if(!m_signature.empty()) {
      if(m_scheme.is_set()) {
         buf.push_back(get_byte<0>(m_scheme.wire_code()));
         buf.push_back(get_byte<1>(m_scheme.wire_code()));
      }

      append_tls_length_value(buf, m_signature, 2);
   }

   return buf;
}

/**
* Verify a Server Key Exchange message
*/
bool Server_Key_Exchange::verify(const Public_Key& server_key,
                                 const Handshake_State& state,
                                 const Policy& policy) const {
   policy.check_peer_key_acceptable(server_key);

   std::pair<std::string, Signature_Format> format =
      state.parse_sig_format(server_key, m_scheme, state.client_hello()->signature_schemes(), false, policy);

   std::vector<uint8_t> buf = state.client_hello()->random();

   buf += state.server_hello()->random();
   buf += params();

   const bool signature_valid =
      state.callbacks().tls_verify_message(server_key, format.first, format.second, buf, m_signature);

#if defined(BOTAN_UNSAFE_FUZZER_MODE)
   BOTAN_UNUSED(signature_valid);
   return true;
#else
   return signature_valid;
#endif
}

const PK_Key_Agreement_Key& Server_Key_Exchange::server_kex_key() const {
   BOTAN_ASSERT_NONNULL(m_kex_key);
   return *m_kex_key;
}

}  // namespace Botan::TLS
