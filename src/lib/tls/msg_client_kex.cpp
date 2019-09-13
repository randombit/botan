/*
* Client Key Exchange Message
* (C) 2004-2010,2016 Jack Lloyd
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>
#include <botan/tls_extensions.h>
#include <botan/rng.h>

#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/credentials_manager.h>
#include <botan/internal/ct_utils.h>

#include <botan/rsa.h>

#if defined(BOTAN_HAS_CECPQ1)
  #include <botan/cecpq1.h>
#endif

#if defined(BOTAN_HAS_SRP6)
  #include <botan/srp6.h>
#endif

namespace Botan {

namespace TLS {

/*
* Create a new Client Key Exchange message
*/
Client_Key_Exchange::Client_Key_Exchange(Handshake_IO& io,
                                         Handshake_State& state,
                                         const Policy& policy,
                                         Credentials_Manager& creds,
                                         const Public_Key* server_public_key,
                                         const std::string& hostname,
                                         RandomNumberGenerator& rng)
   {
   const Kex_Algo kex_algo = state.ciphersuite().kex_method();

   if(kex_algo == Kex_Algo::PSK)
      {
      std::string identity_hint = "";

      if(state.server_kex())
         {
         TLS_Data_Reader reader("ClientKeyExchange", state.server_kex()->params());
         identity_hint = reader.get_string(2, 0, 65535);
         }

      const std::string psk_identity =
         creds.psk_identity("tls-client", hostname, identity_hint);

      append_tls_length_value(m_key_material, psk_identity, 2);

      SymmetricKey psk = creds.psk("tls-client", hostname, psk_identity);

      std::vector<uint8_t> zeros(psk.length());

      append_tls_length_value(m_pre_master, zeros, 2);
      append_tls_length_value(m_pre_master, psk.bits_of(), 2);
      }
   else if(state.server_kex())
      {
      TLS_Data_Reader reader("ClientKeyExchange", state.server_kex()->params());

      SymmetricKey psk;

      if(kex_algo == Kex_Algo::DHE_PSK ||
         kex_algo == Kex_Algo::ECDHE_PSK)
         {
         std::string identity_hint = reader.get_string(2, 0, 65535);

         const std::string psk_identity =
            creds.psk_identity("tls-client", hostname, identity_hint);

         append_tls_length_value(m_key_material, psk_identity, 2);

         psk = creds.psk("tls-client", hostname, psk_identity);
         }

      if(kex_algo == Kex_Algo::DH ||
         kex_algo == Kex_Algo::DHE_PSK)
         {
         const std::vector<uint8_t> modulus = reader.get_range<uint8_t>(2, 1, 65535);
         const std::vector<uint8_t> generator = reader.get_range<uint8_t>(2, 1, 65535);
         const std::vector<uint8_t> peer_public_value = reader.get_range<uint8_t>(2, 1, 65535);

         if(reader.remaining_bytes())
            throw Decoding_Error("Bad params size for DH key exchange");

         const std::pair<secure_vector<uint8_t>, std::vector<uint8_t>> dh_result =
            state.callbacks().tls_dh_agree(modulus, generator, peer_public_value, policy, rng);

         if(kex_algo == Kex_Algo::DH)
            m_pre_master = dh_result.first;
         else
            {
            append_tls_length_value(m_pre_master, dh_result.first, 2);
            append_tls_length_value(m_pre_master, psk.bits_of(), 2);
            }

         append_tls_length_value(m_key_material, dh_result.second, 2);
         }
      else if(kex_algo == Kex_Algo::ECDH ||
              kex_algo == Kex_Algo::ECDHE_PSK)
         {
         const uint8_t curve_type = reader.get_byte();
         if(curve_type != 3)
            throw Decoding_Error("Server sent non-named ECC curve");

         const Group_Params curve_id = static_cast<Group_Params>(reader.get_uint16_t());
         const std::vector<uint8_t> peer_public_value = reader.get_range<uint8_t>(1, 1, 255);

         if(policy.choose_key_exchange_group({curve_id}) != curve_id)
            {
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                "Server sent ECC curve prohibited by policy");
            }

         const std::string curve_name = state.callbacks().tls_decode_group_param(curve_id);

         if(curve_name == "")
            throw Decoding_Error("Server sent unknown named curve " +
                                 std::to_string(static_cast<uint16_t>(curve_id)));

         const std::pair<secure_vector<uint8_t>, std::vector<uint8_t>> ecdh_result =
            state.callbacks().tls_ecdh_agree(curve_name, peer_public_value, policy, rng,
                                             state.server_hello()->prefers_compressed_ec_points());

         if(kex_algo == Kex_Algo::ECDH)
            {
            m_pre_master = ecdh_result.first;
            }
         else
            {
            append_tls_length_value(m_pre_master, ecdh_result.first, 2);
            append_tls_length_value(m_pre_master, psk.bits_of(), 2);
            }

         append_tls_length_value(m_key_material, ecdh_result.second, 1);
         }
#if defined(BOTAN_HAS_SRP6)
      else if(kex_algo == Kex_Algo::SRP_SHA)
         {
         const BigInt N = BigInt::decode(reader.get_range<uint8_t>(2, 1, 65535));
         const BigInt g = BigInt::decode(reader.get_range<uint8_t>(2, 1, 65535));
         std::vector<uint8_t> salt = reader.get_range<uint8_t>(1, 1, 255);
         const BigInt B = BigInt::decode(reader.get_range<uint8_t>(2, 1, 65535));

         const std::string srp_group = srp6_group_identifier(N, g);

         const std::string srp_identifier =
            creds.srp_identifier("tls-client", hostname);

         const std::string srp_password =
            creds.srp_password("tls-client", hostname, srp_identifier);

         std::pair<BigInt, SymmetricKey> srp_vals =
            srp6_client_agree(srp_identifier,
                              srp_password,
                              srp_group,
                              "SHA-1",
                              salt,
                              B,
                              rng);

         append_tls_length_value(m_key_material, BigInt::encode(srp_vals.first), 2);
         m_pre_master = srp_vals.second.bits_of();
         }
#endif

#if defined(BOTAN_HAS_CECPQ1)
      else if(kex_algo == Kex_Algo::CECPQ1)
         {
         const std::vector<uint8_t> cecpq1_offer = reader.get_range<uint8_t>(2, 1, 65535);

         if(cecpq1_offer.size() != CECPQ1_OFFER_BYTES)
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE, "Invalid CECPQ1 key size");

         std::vector<uint8_t> newhope_accept(CECPQ1_ACCEPT_BYTES);
         secure_vector<uint8_t> shared_secret(CECPQ1_SHARED_KEY_BYTES);
         CECPQ1_accept(shared_secret.data(), newhope_accept.data(), cecpq1_offer.data(), rng);
         append_tls_length_value(m_key_material, newhope_accept, 2);
         m_pre_master = shared_secret;
         }
#endif
      else
         {
         throw Internal_Error("Client_Key_Exchange: Unknown key exchange method was negotiated");
         }

      reader.assert_done();
      }
   else
      {
      // No server key exchange msg better mean RSA kex + RSA key in cert

      if(kex_algo != Kex_Algo::STATIC_RSA)
         throw Unexpected_Message("No server kex message, but negotiated a key exchange that required it");

      if(!server_public_key)
         throw Internal_Error("No server public key for RSA exchange");

      if(auto rsa_pub = dynamic_cast<const RSA_PublicKey*>(server_public_key))
         {
         const Protocol_Version offered_version = state.client_hello()->version();

         rng.random_vec(m_pre_master, 48);
         m_pre_master[0] = offered_version.major_version();
         m_pre_master[1] = offered_version.minor_version();

         PK_Encryptor_EME encryptor(*rsa_pub, rng, "PKCS1v15");

         const std::vector<uint8_t> encrypted_key = encryptor.encrypt(m_pre_master, rng);

         append_tls_length_value(m_key_material, encrypted_key, 2);
         }
      else
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Expected a RSA key in server cert but got " +
                             server_public_key->algo_name());
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
                                         RandomNumberGenerator& rng)
   {
   const Kex_Algo kex_algo = state.ciphersuite().kex_method();

   if(kex_algo == Kex_Algo::STATIC_RSA)
      {
      BOTAN_ASSERT(state.server_certs() && !state.server_certs()->cert_chain().empty(),
                   "RSA key exchange negotiated so server sent a certificate");

      if(!server_rsa_kex_key)
         throw Internal_Error("Expected RSA kex but no server kex key set");

      if(!dynamic_cast<const RSA_PrivateKey*>(server_rsa_kex_key))
         throw Internal_Error("Expected RSA key but got " + server_rsa_kex_key->algo_name());

      TLS_Data_Reader reader("ClientKeyExchange", contents);
      const std::vector<uint8_t> encrypted_pre_master = reader.get_range<uint8_t>(2, 0, 65535);
      reader.assert_done();

      PK_Decryptor_EME decryptor(*server_rsa_kex_key, rng, "PKCS1v15");

      const uint8_t client_major = state.client_hello()->version().major_version();
      const uint8_t client_minor = state.client_hello()->version().minor_version();

      /*
      * PK_Decryptor::decrypt_or_random will return a random value if
      * either the length does not match the expected value or if the
      * version number embedded in the PMS does not match the one sent
      * in the client hello.
      */
      const size_t expected_plaintext_size = 48;
      const size_t expected_content_size = 2;
      const uint8_t expected_content_bytes[expected_content_size] = { client_major, client_minor };
      const uint8_t expected_content_pos[expected_content_size] = { 0, 1 };

      m_pre_master =
         decryptor.decrypt_or_random(encrypted_pre_master.data(),
                                     encrypted_pre_master.size(),
                                     expected_plaintext_size,
                                     rng,
                                     expected_content_bytes,
                                     expected_content_pos,
                                     expected_content_size);
      }
   else
      {
      TLS_Data_Reader reader("ClientKeyExchange", contents);

      SymmetricKey psk;

      if(key_exchange_is_psk(kex_algo))
         {
         const std::string psk_identity = reader.get_string(2, 0, 65535);

         psk = creds.psk("tls-server",
                         state.client_hello()->sni_hostname(),
                         psk_identity);

         if(psk.length() == 0)
            {
            if(policy.hide_unknown_users())
               psk = SymmetricKey(rng, 16);
            else
               throw TLS_Exception(Alert::UNKNOWN_PSK_IDENTITY,
                                   "No PSK for identifier " + psk_identity);
            }
         }

      if(kex_algo == Kex_Algo::PSK)
         {
         std::vector<uint8_t> zeros(psk.length());
         append_tls_length_value(m_pre_master, zeros, 2);
         append_tls_length_value(m_pre_master, psk.bits_of(), 2);
         }
#if defined(BOTAN_HAS_SRP6)
      else if(kex_algo == Kex_Algo::SRP_SHA)
         {
         SRP6_Server_Session& srp = state.server_kex()->server_srp_params();

         m_pre_master = srp.step2(BigInt::decode(reader.get_range<uint8_t>(2, 0, 65535))).bits_of();
         }
#endif
#if defined(BOTAN_HAS_CECPQ1)
      else if(kex_algo == Kex_Algo::CECPQ1)
         {
         const CECPQ1_key& cecpq1_offer = state.server_kex()->cecpq1_key();

         const std::vector<uint8_t> cecpq1_accept = reader.get_range<uint8_t>(2, 0, 65535);
         if(cecpq1_accept.size() != CECPQ1_ACCEPT_BYTES)
            throw Decoding_Error("Invalid size for CECPQ1 accept message");

         m_pre_master.resize(CECPQ1_SHARED_KEY_BYTES);
         CECPQ1_finish(m_pre_master.data(), cecpq1_offer, cecpq1_accept.data());
         }
#endif
      else if(kex_algo == Kex_Algo::DH ||
              kex_algo == Kex_Algo::DHE_PSK ||
              kex_algo == Kex_Algo::ECDH ||
              kex_algo == Kex_Algo::ECDHE_PSK)
         {
         const Private_Key& private_key = state.server_kex()->server_kex_key();

         const PK_Key_Agreement_Key* ka_key =
            dynamic_cast<const PK_Key_Agreement_Key*>(&private_key);

         if(!ka_key)
            throw Internal_Error("Expected key agreement key type but got " +
                                 private_key.algo_name());

         std::vector<uint8_t> client_pubkey;

         if(ka_key->algo_name() == "DH")
            {
            client_pubkey = reader.get_range<uint8_t>(2, 0, 65535);
            }
         else
            {
            client_pubkey = reader.get_range<uint8_t>(1, 1, 255);
            }

         try
            {
            PK_Key_Agreement ka(*ka_key, rng, "Raw");

            secure_vector<uint8_t> shared_secret = ka.derive_key(0, client_pubkey).bits_of();

            if(ka_key->algo_name() == "DH")
               shared_secret = CT::strip_leading_zeros(shared_secret);

            if(kex_algo == Kex_Algo::DHE_PSK ||
               kex_algo == Kex_Algo::ECDHE_PSK)
               {
               append_tls_length_value(m_pre_master, shared_secret, 2);
               append_tls_length_value(m_pre_master, psk.bits_of(), 2);
               }
            else
               m_pre_master = shared_secret;
            }
         catch(Invalid_Argument& e)
            {
            throw TLS_Exception(Alert::ILLEGAL_PARAMETER, e.what());
            }
         catch(std::exception&)
            {
            /*
            * Something failed in the DH/ECDH computation. To avoid possible
            * attacks which are based on triggering and detecting some edge
            * failure condition, randomize the pre-master output and carry on,
            * allowing the protocol to fail later in the finished checks.
            */
            rng.random_vec(m_pre_master, ka_key->public_value().size());
            }

         reader.assert_done();
         }
      else
         throw Internal_Error("Client_Key_Exchange: Unknown key exchange negotiated");
      }
   }

}

}
