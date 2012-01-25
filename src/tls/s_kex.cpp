/*
* Server Key Exchange Message
* (C) 2004-2010,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_extensions.h>
#include <botan/internal/assert.h>
#include <botan/loadstor.h>
#include <botan/pubkey.h>
#include <botan/dh.h>
#include <botan/ecdh.h>
#include <botan/rsa.h>
#include <botan/oids.h>
#include <memory>

#include <stdio.h>

namespace Botan {

namespace TLS {

/**
* Create a new Server Key Exchange message
*/
Server_Key_Exchange::Server_Key_Exchange(Record_Writer& writer,
                                         Handshake_State* state,
                                         const Policy& policy,
                                         RandomNumberGenerator& rng,
                                         const Private_Key* signing_key)
   {
   const std::string kex_algo = state->suite.kex_algo();

   if(kex_algo == "DH")
      {
      std::auto_ptr<DH_PrivateKey> dh(new DH_PrivateKey(rng, policy.dh_group()));

      append_tls_length_value(m_params, BigInt::encode(dh->get_domain().get_p()), 2);
      append_tls_length_value(m_params, BigInt::encode(dh->get_domain().get_g()), 2);
      append_tls_length_value(m_params, dh->public_value(), 2);
      m_kex_key = dh.release();
      }
   else if(kex_algo == "ECDH")
      {
      const std::vector<std::string>& curves =
         state->client_hello->supported_ecc_curves();

      if(curves.empty())
         throw Internal_Error("Client sent no ECC extension but we negotiated ECDH");

      const std::string curve_name = policy.choose_curve(curves);

      if(curve_name == "")
         throw TLS_Exception(HANDSHAKE_FAILURE,
                             "Could not agree on an ECC curve with the client");

      EC_Group ec_group(curve_name);

      std::auto_ptr<ECDH_PrivateKey> ecdh(new ECDH_PrivateKey(rng, ec_group));

      const std::string ecdh_domain_oid = ecdh->domain().get_oid();
      const std::string domain = OIDS::lookup(OID(ecdh_domain_oid));

      if(domain == "")
         throw Internal_Error("Could not find name of ECDH domain " + ecdh_domain_oid);

      const u16bit named_curve_id = Supported_Elliptic_Curves::name_to_curve_id(domain);

      m_params.push_back(3); // named curve
      m_params.push_back(get_byte(0, named_curve_id));
      m_params.push_back(get_byte(1, named_curve_id));

      append_tls_length_value(m_params, ecdh->public_value(), 1);

      m_kex_key = ecdh.release();
      }
   else
      throw Internal_Error("Server_Key_Exchange: Unknown kex type " + kex_algo);

   if(state->suite.sig_algo() != "")
      {
      BOTAN_ASSERT(signing_key, "No signing key set");

      std::pair<std::string, Signature_Format> format =
         state->choose_sig_format(signing_key, m_hash_algo, m_sig_algo, false);

      PK_Signer signer(*signing_key, format.first, format.second);

      signer.update(state->client_hello->random());
      signer.update(state->server_hello->random());
      signer.update(params());
      m_signature = signer.signature(rng);
      }

   send(writer, state->hash);
   }

/**
* Deserialize a Server Key Exchange message
*/
Server_Key_Exchange::Server_Key_Exchange(const MemoryRegion<byte>& buf,
                                         const std::string& kex_algo,
                                         const std::string& sig_algo,
                                         Protocol_Version version) :
   m_kex_key(0)
   {
   if(buf.size() < 6)
      throw Decoding_Error("Server_Key_Exchange: Packet corrupted");

   TLS_Data_Reader reader(buf);

   /*
   * We really are just serializing things back to what they were
   * before, but unfortunately to know where the signature is we need
   * to be able to parse the whole thing anyway.
   */

   if(kex_algo == "DH")
      {
      // 3 bigints, DH p, g, Y

      for(size_t i = 0; i != 3; ++i)
         {
         BigInt v = BigInt::decode(reader.get_range<byte>(2, 1, 65535));
         append_tls_length_value(m_params, BigInt::encode(v), 2);
         }
      }
   else if(kex_algo == "ECDH")
      {
      const byte curve_type = reader.get_byte();

      if(curve_type != 3)
         throw Decoding_Error("Server_Key_Exchange: Server sent non-named ECC curve");

      const u16bit curve_id = reader.get_u16bit();

      const std::string name = Supported_Elliptic_Curves::curve_id_to_name(curve_id);

      MemoryVector<byte> ecdh_key = reader.get_range<byte>(1, 1, 255);

      if(name == "")
         throw Decoding_Error("Server_Key_Exchange: Server sent unknown named curve " +
                              to_string(curve_id));

      m_params.push_back(curve_type);
      m_params.push_back(get_byte(0, curve_id));
      m_params.push_back(get_byte(1, curve_id));
      append_tls_length_value(m_params, ecdh_key, 1);
      }
   else
      throw Decoding_Error("Server_Key_Exchange: Unsupported server key exchange type " +
                           kex_algo);

   if(sig_algo != "")
      {
      if(version >= Protocol_Version::TLS_V12)
         {
         m_hash_algo = Signature_Algorithms::hash_algo_name(reader.get_byte());
         m_sig_algo = Signature_Algorithms::sig_algo_name(reader.get_byte());
         }

      m_signature = reader.get_range<byte>(2, 0, 65535);
      }
   }


/**
* Serialize a Server Key Exchange message
*/
MemoryVector<byte> Server_Key_Exchange::serialize() const
   {
   MemoryVector<byte> buf = params();

   // This should be an explicit version check
   if(m_hash_algo != "" && m_sig_algo != "")
      {
      buf.push_back(Signature_Algorithms::hash_algo_code(m_hash_algo));
      buf.push_back(Signature_Algorithms::sig_algo_code(m_sig_algo));
      }

   append_tls_length_value(buf, m_signature, 2);
   return buf;
   }

/**
* Verify a Server Key Exchange message
*/
bool Server_Key_Exchange::verify(const X509_Certificate& cert,
                                 Handshake_State* state) const
   {
   std::auto_ptr<Public_Key> key(cert.subject_public_key());

   std::pair<std::string, Signature_Format> format =
      state->understand_sig_format(key.get(), m_hash_algo, m_sig_algo, false);

   PK_Verifier verifier(*key, format.first, format.second);

   verifier.update(state->client_hello->random());
   verifier.update(state->server_hello->random());
   verifier.update(params());

   return verifier.check_signature(m_signature);
   }

const Private_Key& Server_Key_Exchange::server_kex_key() const
   {
   BOTAN_ASSERT(m_kex_key, "Key is non-NULL");
   return *m_kex_key;
   }
}

}
