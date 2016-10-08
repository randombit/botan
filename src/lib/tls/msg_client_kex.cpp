/*
* Client Key Exchange Message
* (C) 2004-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_extensions.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/credentials_manager.h>
#include <botan/rng.h>
#include <botan/loadstor.h>
#include <botan/internal/ct_utils.h>

#include <botan/pubkey.h>

#include <botan/dh.h>
#include <botan/ecdh.h>
#include <botan/rsa.h>

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
   const std::string kex_algo = state.ciphersuite().kex_algo();

   if(kex_algo == "PSK")
      {
      std::string identity_hint = "";

      if(state.server_kex())
         {
         TLS_Data_Reader reader("ClientKeyExchange", state.server_kex()->params());
         identity_hint = reader.get_string(2, 0, 65535);
         }

      const std::string psk_identity = creds.psk_identity("tls-client",
                                                          hostname,
                                                          identity_hint);

      append_tls_length_value(m_key_material, psk_identity, 2);

      SymmetricKey psk = creds.psk("tls-client", hostname, psk_identity);

      std::vector<byte> zeros(psk.length());

      append_tls_length_value(m_pre_master, zeros, 2);
      append_tls_length_value(m_pre_master, psk.bits_of(), 2);
      }
   else if(state.server_kex())
      {
      TLS_Data_Reader reader("ClientKeyExchange", state.server_kex()->params());

      SymmetricKey psk;

      if(kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
         {
         std::string identity_hint = reader.get_string(2, 0, 65535);

         const std::string psk_identity = creds.psk_identity("tls-client",
                                                             hostname,
                                                             identity_hint);

         append_tls_length_value(m_key_material, psk_identity, 2);

         psk = creds.psk("tls-client", hostname, psk_identity);
         }

      if(kex_algo == "DH" || kex_algo == "DHE_PSK")
         {
         BigInt p = BigInt::decode(reader.get_range<byte>(2, 1, 65535));
         BigInt g = BigInt::decode(reader.get_range<byte>(2, 1, 65535));
         BigInt Y = BigInt::decode(reader.get_range<byte>(2, 1, 65535));

         if(reader.remaining_bytes())
            throw Decoding_Error("Bad params size for DH key exchange");

         /*
         * A basic check for key validity. As we do not know q here we
         * cannot check that Y is in the right subgroup. However since
         * our key is ephemeral there does not seem to be any
         * advantage to bogus keys anyway.
         */
         if(Y <= 1 || Y >= p - 1)
            throw TLS_Exception(Alert::INSUFFICIENT_SECURITY,
                                "Server sent bad DH key for DHE exchange");

         DL_Group group(p, g);

         if(!group.verify_group(rng, false))
            throw TLS_Exception(Alert::INSUFFICIENT_SECURITY,
                                "DH group validation failed");

         DH_PublicKey counterparty_key(group, Y);

         policy.check_peer_key_acceptable(counterparty_key);

         DH_PrivateKey priv_key(rng, group);

         PK_Key_Agreement ka(priv_key, rng, "Raw");

         secure_vector<byte> dh_secret = CT::strip_leading_zeros(
            ka.derive_key(0, counterparty_key.public_value()).bits_of());

         if(kex_algo == "DH")
            m_pre_master = dh_secret;
         else
            {
            append_tls_length_value(m_pre_master, dh_secret, 2);
            append_tls_length_value(m_pre_master, psk.bits_of(), 2);
            }

         append_tls_length_value(m_key_material, priv_key.public_value(), 2);
         }
      else if(kex_algo == "ECDH" || kex_algo == "ECDHE_PSK")
         {
         const byte curve_type = reader.get_byte();

         if(curve_type != 3)
            throw Decoding_Error("Server sent non-named ECC curve");

         const u16bit curve_id = reader.get_u16bit();

         const std::string name = Supported_Elliptic_Curves::curve_id_to_name(curve_id);

         if(name == "")
            throw Decoding_Error("Server sent unknown named curve " + std::to_string(curve_id));

         if(!policy.allowed_ecc_curve(name))
            {
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                "Server sent ECC curve prohibited by policy");
            }

         EC_Group group(name);

         std::vector<byte> ecdh_key = reader.get_range<byte>(1, 1, 255);

         ECDH_PublicKey counterparty_key(group, OS2ECP(ecdh_key, group.get_curve()));

         policy.check_peer_key_acceptable(counterparty_key);
         
         ECDH_PrivateKey priv_key(rng, group);

         PK_Key_Agreement ka(priv_key, rng, "Raw");

         secure_vector<byte> ecdh_secret =
            ka.derive_key(0, counterparty_key.public_value()).bits_of();

         if(kex_algo == "ECDH")
            m_pre_master = ecdh_secret;
         else
            {
            append_tls_length_value(m_pre_master, ecdh_secret, 2);
            append_tls_length_value(m_pre_master, psk.bits_of(), 2);
            }

         // follow server's preference for point compression
         append_tls_length_value(m_key_material,
               priv_key.public_value(state.server_hello()->prefers_compressed_ec_points() ?
               PointGFp::COMPRESSED : PointGFp::UNCOMPRESSED ), 1);
         }
#if defined(BOTAN_HAS_SRP6)
      else if(kex_algo == "SRP_SHA")
         {
         const BigInt N = BigInt::decode(reader.get_range<byte>(2, 1, 65535));
         const BigInt g = BigInt::decode(reader.get_range<byte>(2, 1, 65535));
         std::vector<byte> salt = reader.get_range<byte>(1, 1, 255);
         const BigInt B = BigInt::decode(reader.get_range<byte>(2, 1, 65535));

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
      else
         {
         throw Internal_Error("Client_Key_Exchange: Unknown kex " +
                              kex_algo);
         }

      reader.assert_done();
      }
   else
      {
      // No server key exchange msg better mean RSA kex + RSA key in cert

      if(kex_algo != "RSA")
         throw Unexpected_Message("No server kex but negotiated kex " + kex_algo);

      if(!server_public_key)
         throw Internal_Error("No server public key for RSA exchange");

      if(auto rsa_pub = dynamic_cast<const RSA_PublicKey*>(server_public_key))
         {
         const Protocol_Version offered_version = state.client_hello()->version();

         m_pre_master = rng.random_vec(48);
         m_pre_master[0] = offered_version.major_version();
         m_pre_master[1] = offered_version.minor_version();

         PK_Encryptor_EME encryptor(*rsa_pub, rng, "PKCS1v15");

         const std::vector<byte> encrypted_key = encryptor.encrypt(m_pre_master, rng);

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
Client_Key_Exchange::Client_Key_Exchange(const std::vector<byte>& contents,
                                         const Handshake_State& state,
                                         const Private_Key* server_rsa_kex_key,
                                         Credentials_Manager& creds,
                                         const Policy& policy,
                                         RandomNumberGenerator& rng)
   {
   const std::string kex_algo = state.ciphersuite().kex_algo();

   if(kex_algo == "RSA")
      {
      BOTAN_ASSERT(state.server_certs() && !state.server_certs()->cert_chain().empty(),
                   "RSA key exchange negotiated so server sent a certificate");

      if(!server_rsa_kex_key)
         throw Internal_Error("Expected RSA kex but no server kex key set");

      if(!dynamic_cast<const RSA_PrivateKey*>(server_rsa_kex_key))
         throw Internal_Error("Expected RSA key but got " + server_rsa_kex_key->algo_name());

      TLS_Data_Reader reader("ClientKeyExchange", contents);
      const std::vector<byte> encrypted_pre_master = reader.get_range<byte>(2, 0, 65535);

      PK_Decryptor_EME decryptor(*server_rsa_kex_key, rng, "PKCS1v15");

      const byte client_major = state.client_hello()->version().major_version();
      const byte client_minor = state.client_hello()->version().minor_version();

      /*
      * PK_Decryptor::decrypt_or_random will return a random value if
      * either the length does not match the expected value or if the
      * version number embedded in the PMS does not match the one sent
      * in the client hello.
      */
      const size_t expected_plaintext_size = 48;
      const size_t expected_content_size = 2;
      const byte expected_content_bytes[expected_content_size] = { client_major, client_minor };
      const byte expected_content_pos[expected_content_size] = { 0, 1 };

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

      if(kex_algo == "PSK" || kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
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

      if(kex_algo == "PSK")
         {
         std::vector<byte> zeros(psk.length());
         append_tls_length_value(m_pre_master, zeros, 2);
         append_tls_length_value(m_pre_master, psk.bits_of(), 2);
         }
#if defined(BOTAN_HAS_SRP6)
      else if(kex_algo == "SRP_SHA")
         {
         SRP6_Server_Session& srp = state.server_kex()->server_srp_params();

         m_pre_master = srp.step2(BigInt::decode(reader.get_range<byte>(2, 0, 65535))).bits_of();
         }
#endif
      else if(kex_algo == "DH" || kex_algo == "DHE_PSK" ||
              kex_algo == "ECDH" || kex_algo == "ECDHE_PSK")
         {
         const Private_Key& private_key = state.server_kex()->server_kex_key();

         const PK_Key_Agreement_Key* ka_key =
            dynamic_cast<const PK_Key_Agreement_Key*>(&private_key);

         if(!ka_key)
            throw Internal_Error("Expected key agreement key type but got " +
                                 private_key.algo_name());

         try
            {
            PK_Key_Agreement ka(*ka_key, rng, "Raw");

            std::vector<byte> client_pubkey;

            if(ka_key->algo_name() == "DH")
               client_pubkey = reader.get_range<byte>(2, 0, 65535);
            else
               client_pubkey = reader.get_range<byte>(1, 0, 255);

            secure_vector<byte> shared_secret = ka.derive_key(0, client_pubkey).bits_of();

            if(ka_key->algo_name() == "DH")
               shared_secret = CT::strip_leading_zeros(shared_secret);

            if(kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
               {
               append_tls_length_value(m_pre_master, shared_secret, 2);
               append_tls_length_value(m_pre_master, psk.bits_of(), 2);
               }
            else
               m_pre_master = shared_secret;
            }
         catch(std::exception &)
            {
            /*
            * Something failed in the DH computation. To avoid possible
            * timing attacks, randomize the pre-master output and carry
            * on, allowing the protocol to fail later in the finished
            * checks.
            */
            m_pre_master = rng.random_vec(ka_key->public_value().size());
            }
         }
      else
         throw Internal_Error("Client_Key_Exchange: Unknown kex type " + kex_algo);
      }
   }

}

}
