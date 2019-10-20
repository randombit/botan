/*
* Server Key Exchange Message
* (C) 2004-2010,2012,2015,2016 Jack Lloyd
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>
#include <botan/tls_extensions.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/credentials_manager.h>
#include <botan/loadstor.h>
#include <botan/pubkey.h>

#include <botan/dh.h>
#include <botan/ecdh.h>

#if defined(BOTAN_HAS_CURVE_25519)
  #include <botan/curve25519.h>
#endif

#if defined(BOTAN_HAS_CECPQ1)
  #include <botan/cecpq1.h>
#endif

#if defined(BOTAN_HAS_SRP6)
  #include <botan/srp6.h>
#endif

namespace Botan {

namespace TLS {

/**
* Create a new Server Key Exchange message
*/
Server_Key_Exchange::Server_Key_Exchange(Handshake_IO& io,
                                         Handshake_State& state,
                                         const Policy& policy,
                                         Credentials_Manager& creds,
                                         RandomNumberGenerator& rng,
                                         const Private_Key* signing_key)
   {
   const std::string hostname = state.client_hello()->sni_hostname();
   const Kex_Algo kex_algo = state.ciphersuite().kex_method();

   if(kex_algo == Kex_Algo::PSK || kex_algo == Kex_Algo::DHE_PSK || kex_algo == Kex_Algo::ECDHE_PSK)
      {
      std::string identity_hint =
         creds.psk_identity_hint("tls-server", hostname);

      append_tls_length_value(m_params, identity_hint, 2);
      }

   if(kex_algo == Kex_Algo::DH || kex_algo == Kex_Algo::DHE_PSK)
      {
      const std::vector<Group_Params> dh_groups = state.client_hello()->supported_dh_groups();

      Group_Params shared_group = Group_Params::NONE;

      /*
      If the client does not send any DH groups in the supported groups
      extension, but does offer DH ciphersuites, we select a group arbitrarily
      */

      if(dh_groups.empty())
         {
         shared_group = policy.default_dh_group();
         }
      else
         {
         shared_group = policy.choose_key_exchange_group(dh_groups);
         }

      if(shared_group == Group_Params::NONE)
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
               "Could not agree on a DH group with the client");

      BOTAN_ASSERT(group_param_is_dh(shared_group), "DH groups for the DH ciphersuites god");

      const std::string group_name = state.callbacks().tls_decode_group_param(shared_group);
      std::unique_ptr<DH_PrivateKey> dh(new DH_PrivateKey(rng, DL_Group(group_name)));

      append_tls_length_value(m_params, BigInt::encode(dh->get_domain().get_p()), 2);
      append_tls_length_value(m_params, BigInt::encode(dh->get_domain().get_g()), 2);
      append_tls_length_value(m_params, dh->public_value(), 2);
      m_kex_key.reset(dh.release());
      }
   else if(kex_algo == Kex_Algo::ECDH || kex_algo == Kex_Algo::ECDHE_PSK)
      {
      const std::vector<Group_Params> ec_groups = state.client_hello()->supported_ecc_curves();

      if(ec_groups.empty())
         throw Internal_Error("Client sent no ECC extension but we negotiated ECDH");

      Group_Params shared_group = policy.choose_key_exchange_group(ec_groups);

      if(shared_group == Group_Params::NONE)
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE, "No shared ECC group with client");

      std::vector<uint8_t> ecdh_public_val;

      if(shared_group == Group_Params::X25519)
         {
#if defined(BOTAN_HAS_CURVE_25519)
         std::unique_ptr<Curve25519_PrivateKey> x25519(new Curve25519_PrivateKey(rng));
         ecdh_public_val = x25519->public_value();
         m_kex_key.reset(x25519.release());
#else
         throw Internal_Error("Negotiated X25519 somehow, but it is disabled");
#endif
         }
      else
         {
         Group_Params curve = policy.choose_key_exchange_group(ec_groups);

         const std::string curve_name = state.callbacks().tls_decode_group_param(curve);

         EC_Group ec_group(curve_name);
         std::unique_ptr<ECDH_PrivateKey> ecdh(new ECDH_PrivateKey(rng, ec_group));

         // follow client's preference for point compression
         ecdh_public_val = ecdh->public_value(
            state.client_hello()->prefers_compressed_ec_points() ?
            PointGFp::COMPRESSED : PointGFp::UNCOMPRESSED);

         m_kex_key.reset(ecdh.release());
         }

      const uint16_t named_curve_id = static_cast<uint16_t>(shared_group);
      m_params.push_back(3); // named curve
      m_params.push_back(get_byte(0, named_curve_id));
      m_params.push_back(get_byte(1, named_curve_id));

      append_tls_length_value(m_params, ecdh_public_val, 1);
      }
#if defined(BOTAN_HAS_SRP6)
   else if(kex_algo == Kex_Algo::SRP_SHA)
      {
      const std::string srp_identifier = state.client_hello()->srp_identifier();

      std::string group_id;
      BigInt v;
      std::vector<uint8_t> salt;

      const bool found = creds.srp_verifier("tls-server", hostname,
                                            srp_identifier,
                                            group_id, v, salt,
                                            policy.hide_unknown_users());

      if(!found)
         throw TLS_Exception(Alert::UNKNOWN_PSK_IDENTITY,
                             "Unknown SRP user " + srp_identifier);

      m_srp_params.reset(new SRP6_Server_Session);

      BigInt B = m_srp_params->step1(v, group_id,
                                     "SHA-1", rng);

      DL_Group group(group_id);

      append_tls_length_value(m_params, BigInt::encode(group.get_p()), 2);
      append_tls_length_value(m_params, BigInt::encode(group.get_g()), 2);
      append_tls_length_value(m_params, salt, 1);
      append_tls_length_value(m_params, BigInt::encode(B), 2);
      }
#endif
#if defined(BOTAN_HAS_CECPQ1)
   else if(kex_algo == Kex_Algo::CECPQ1)
      {
      std::vector<uint8_t> cecpq1_offer(CECPQ1_OFFER_BYTES);
      m_cecpq1_key.reset(new CECPQ1_key);
      CECPQ1_offer(cecpq1_offer.data(), m_cecpq1_key.get(), rng);
      append_tls_length_value(m_params, cecpq1_offer, 2);
      }
#endif
   else if(kex_algo != Kex_Algo::PSK)
      {
      throw Internal_Error("Server_Key_Exchange: Unknown kex type " +
                           kex_method_to_string(kex_algo));
      }

   if(state.ciphersuite().signature_used())
      {
      BOTAN_ASSERT(signing_key, "Signing key was set");

      std::pair<std::string, Signature_Format> format =
         state.choose_sig_format(*signing_key, m_scheme, false, policy);

      std::vector<uint8_t> buf = state.client_hello()->random();

      buf += state.server_hello()->random();
      buf += params();

      m_signature =
         state.callbacks().tls_sign_message(*signing_key, rng,
                                            format.first, format.second, buf);
      }

   state.hash().update(io.send(*this));
   }

/**
* Deserialize a Server Key Exchange message
*/
Server_Key_Exchange::Server_Key_Exchange(const std::vector<uint8_t>& buf,
                                         const Kex_Algo kex_algo,
                                         const Auth_Method auth_method,
                                         Protocol_Version version)
   {
   TLS_Data_Reader reader("ServerKeyExchange", buf);

   /*
   * Here we are deserializing enough to find out what offset the
   * signature is at. All processing is done when the Client Key Exchange
   * is prepared.
   */

   if(kex_algo == Kex_Algo::PSK || kex_algo == Kex_Algo::DHE_PSK || kex_algo == Kex_Algo::ECDHE_PSK)
      {
      reader.get_string(2, 0, 65535); // identity hint
      }

   if(kex_algo == Kex_Algo::DH || kex_algo == Kex_Algo::DHE_PSK)
      {
      // 3 bigints, DH p, g, Y

      for(size_t i = 0; i != 3; ++i)
         {
         reader.get_range<uint8_t>(2, 1, 65535);
         }
      }
   else if(kex_algo == Kex_Algo::ECDH || kex_algo == Kex_Algo::ECDHE_PSK)
      {
      reader.get_byte(); // curve type
      reader.get_uint16_t(); // curve id
      reader.get_range<uint8_t>(1, 1, 255); // public key
      }
   else if(kex_algo == Kex_Algo::SRP_SHA)
      {
      // 2 bigints (N,g) then salt, then server B

      reader.get_range<uint8_t>(2, 1, 65535);
      reader.get_range<uint8_t>(2, 1, 65535);
      reader.get_range<uint8_t>(1, 1, 255);
      reader.get_range<uint8_t>(2, 1, 65535);
      }
   else if(kex_algo == Kex_Algo::CECPQ1)
      {
      // u16 blob
      reader.get_range<uint8_t>(2, 1, 65535);
      }
   else if(kex_algo != Kex_Algo::PSK)
      throw Decoding_Error("Server_Key_Exchange: Unsupported kex type " +
                           kex_method_to_string(kex_algo));

   m_params.assign(buf.data(), buf.data() + reader.read_so_far());

   if(auth_method != Auth_Method::ANONYMOUS && auth_method != Auth_Method::IMPLICIT)
      {
      if(version.supports_negotiable_signature_algorithms())
         {
         m_scheme = static_cast<Signature_Scheme>(reader.get_uint16_t());
         }

      m_signature = reader.get_range<uint8_t>(2, 0, 65535);
      }

   reader.assert_done();
   }

/**
* Serialize a Server Key Exchange message
*/
std::vector<uint8_t> Server_Key_Exchange::serialize() const
   {
   std::vector<uint8_t> buf = params();

   if(m_signature.size())
      {
      if(m_scheme != Signature_Scheme::NONE)
         {
         const uint16_t scheme_code = static_cast<uint16_t>(m_scheme);
         buf.push_back(get_byte(0, scheme_code));
         buf.push_back(get_byte(1, scheme_code));
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
                                 const Policy& policy) const
   {
   policy.check_peer_key_acceptable(server_key);

   std::pair<std::string, Signature_Format> format =
      state.parse_sig_format(server_key, m_scheme, false, policy);

   std::vector<uint8_t> buf = state.client_hello()->random();

   buf += state.server_hello()->random();
   buf += params();

   const bool signature_valid =
      state.callbacks().tls_verify_message(server_key, format.first, format.second,
                                           buf, m_signature);

#if defined(BOTAN_UNSAFE_FUZZER_MODE)
   BOTAN_UNUSED(signature_valid);
   return true;
#else
   return signature_valid;
#endif
   }

const Private_Key& Server_Key_Exchange::server_kex_key() const
   {
   BOTAN_ASSERT_NONNULL(m_kex_key);
   return *m_kex_key;
   }

}

}
