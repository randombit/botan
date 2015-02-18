/*
* Server Key Exchange Message
* (C) 2004-2010,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_extensions.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/credentials_manager.h>
#include <botan/loadstor.h>
#include <botan/pubkey.h>
#include <botan/dh.h>
#include <botan/ecdh.h>
#include <botan/rsa.h>
#include <botan/srp6.h>
#include <botan/oids.h>

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
   const std::string kex_algo = state.ciphersuite().kex_algo();

   if(kex_algo == "PSK" || kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
      {
      std::string identity_hint =
         creds.psk_identity_hint("tls-server", hostname);

      append_tls_length_value(m_params, identity_hint, 2);
      }

   if(kex_algo == "DH" || kex_algo == "DHE_PSK")
      {
      std::unique_ptr<DH_PrivateKey> dh(new DH_PrivateKey(rng, policy.dh_group()));

      append_tls_length_value(m_params, BigInt::encode(dh->get_domain().get_p()), 2);
      append_tls_length_value(m_params, BigInt::encode(dh->get_domain().get_g()), 2);
      append_tls_length_value(m_params, dh->public_value(), 2);
      m_kex_key.reset(dh.release());
      }
   else if(kex_algo == "ECDH" || kex_algo == "ECDHE_PSK")
      {
      const std::vector<std::string>& curves =
         state.client_hello()->supported_ecc_curves();

      if(curves.empty())
         throw Internal_Error("Client sent no ECC extension but we negotiated ECDH");

      const std::string curve_name = policy.choose_curve(curves);

      if(curve_name == "")
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Could not agree on an ECC curve with the client");

      EC_Group ec_group(curve_name);

      std::unique_ptr<ECDH_PrivateKey> ecdh(new ECDH_PrivateKey(rng, ec_group));

      const std::string ecdh_domain_oid = ecdh->domain().get_oid();
      const std::string domain = OIDS::lookup(OID(ecdh_domain_oid));

      if(domain == "")
         throw Internal_Error("Could not find name of ECDH domain " + ecdh_domain_oid);

      const u16bit named_curve_id = Supported_Elliptic_Curves::name_to_curve_id(domain);

      m_params.push_back(3); // named curve
      m_params.push_back(get_byte(0, named_curve_id));
      m_params.push_back(get_byte(1, named_curve_id));

      append_tls_length_value(m_params, ecdh->public_value(), 1);

      m_kex_key.reset(ecdh.release());
      }
   else if(kex_algo == "SRP_SHA")
      {
      const std::string srp_identifier = state.client_hello()->srp_identifier();

      std::string group_id;
      BigInt v;
      std::vector<byte> salt;

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
   else if(kex_algo != "PSK")
      throw Internal_Error("Server_Key_Exchange: Unknown kex type " + kex_algo);

   if(state.ciphersuite().sig_algo() != "")
      {
      BOTAN_ASSERT(signing_key, "Signing key was set");

      std::pair<std::string, Signature_Format> format =
         state.choose_sig_format(*signing_key, m_hash_algo, m_sig_algo, false, policy);

      PK_Signer signer(*signing_key, format.first, format.second);

      signer.update(state.client_hello()->random());
      signer.update(state.server_hello()->random());
      signer.update(params());
      m_signature = signer.signature(rng);
      }

   state.hash().update(io.send(*this));
   }

/**
* Deserialize a Server Key Exchange message
*/
Server_Key_Exchange::Server_Key_Exchange(const std::vector<byte>& buf,
                                         const std::string& kex_algo,
                                         const std::string& sig_algo,
                                         Protocol_Version version) :
   m_kex_key(nullptr), m_srp_params(nullptr)
   {
   if(buf.size() < 6)
      throw Decoding_Error("Server_Key_Exchange: Packet corrupted");

   TLS_Data_Reader reader("ServerKeyExchange", buf);

   /*
   * We really are just serializing things back to what they were
   * before, but unfortunately to know where the signature is we need
   * to be able to parse the whole thing anyway.
   */

   if(kex_algo == "PSK" || kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
      {
      const std::string identity_hint = reader.get_string(2, 0, 65535);
      append_tls_length_value(m_params, identity_hint, 2);
      }

   if(kex_algo == "DH" || kex_algo == "DHE_PSK")
      {
      // 3 bigints, DH p, g, Y

      for(size_t i = 0; i != 3; ++i)
         {
         BigInt v = BigInt::decode(reader.get_range<byte>(2, 1, 65535));
         append_tls_length_value(m_params, BigInt::encode(v), 2);
         }
      }
   else if(kex_algo == "ECDH" || kex_algo == "ECDHE_PSK")
      {
      const byte curve_type = reader.get_byte();

      if(curve_type != 3)
         throw Decoding_Error("Server_Key_Exchange: Server sent non-named ECC curve");

      const u16bit curve_id = reader.get_u16bit();

      const std::string name = Supported_Elliptic_Curves::curve_id_to_name(curve_id);

      std::vector<byte> ecdh_key = reader.get_range<byte>(1, 1, 255);

      if(name == "")
         throw Decoding_Error("Server_Key_Exchange: Server sent unknown named curve " +
                              std::to_string(curve_id));

      m_params.push_back(curve_type);
      m_params.push_back(get_byte(0, curve_id));
      m_params.push_back(get_byte(1, curve_id));
      append_tls_length_value(m_params, ecdh_key, 1);
      }
   else if(kex_algo == "SRP_SHA")
      {
      // 2 bigints (N,g) then salt, then server B

      const BigInt N = BigInt::decode(reader.get_range<byte>(2, 1, 65535));
      const BigInt g = BigInt::decode(reader.get_range<byte>(2, 1, 65535));
      std::vector<byte> salt = reader.get_range<byte>(1, 1, 255);
      const BigInt B = BigInt::decode(reader.get_range<byte>(2, 1, 65535));

      append_tls_length_value(m_params, BigInt::encode(N), 2);
      append_tls_length_value(m_params, BigInt::encode(g), 2);
      append_tls_length_value(m_params, salt, 1);
      append_tls_length_value(m_params, BigInt::encode(B), 2);
      }
   else if(kex_algo != "PSK")
      throw Decoding_Error("Server_Key_Exchange: Unsupported kex type " + kex_algo);

   if(sig_algo != "")
      {
      if(version.supports_negotiable_signature_algorithms())
         {
         m_hash_algo = Signature_Algorithms::hash_algo_name(reader.get_byte());
         m_sig_algo = Signature_Algorithms::sig_algo_name(reader.get_byte());
         }

      m_signature = reader.get_range<byte>(2, 0, 65535);
      }

   reader.assert_done();
   }

Server_Key_Exchange::~Server_Key_Exchange() {}

/**
* Serialize a Server Key Exchange message
*/
std::vector<byte> Server_Key_Exchange::serialize() const
   {
   std::vector<byte> buf = params();

   if(m_signature.size())
      {
      // This should be an explicit version check
      if(m_hash_algo != "" && m_sig_algo != "")
         {
         buf.push_back(Signature_Algorithms::hash_algo_code(m_hash_algo));
         buf.push_back(Signature_Algorithms::sig_algo_code(m_sig_algo));
         }

      append_tls_length_value(buf, m_signature, 2);
      }

   return buf;
   }

/**
* Verify a Server Key Exchange message
*/
bool Server_Key_Exchange::verify(const Public_Key& server_key,
                                 const Handshake_State& state) const
   {
   std::pair<std::string, Signature_Format> format =
      state.understand_sig_format(server_key, m_hash_algo, m_sig_algo);

   PK_Verifier verifier(server_key, format.first, format.second);

   verifier.update(state.client_hello()->random());
   verifier.update(state.server_hello()->random());
   verifier.update(params());

   return verifier.check_signature(m_signature);
   }

const Private_Key& Server_Key_Exchange::server_kex_key() const
   {
   BOTAN_ASSERT_NONNULL(m_kex_key);
   return *m_kex_key;
   }

// Only valid for SRP negotiation
SRP6_Server_Session& Server_Key_Exchange::server_srp_params() const
   {
   BOTAN_ASSERT_NONNULL(m_srp_params);
   return *m_srp_params;
   }
}

}
