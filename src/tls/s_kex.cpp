/*
* Server Key Exchange Message
* (C) 2004-2010,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_extensions.h>
#include <botan/loadstor.h>
#include <botan/pubkey.h>
#include <botan/dh.h>
#include <memory>

namespace Botan {

namespace TLS {

/**
* Create a new Server Key Exchange message
*/
Server_Key_Exchange::Server_Key_Exchange(Record_Writer& writer,
                                         Handshake_State* state,
                                         RandomNumberGenerator& rng,
                                         const Private_Key* private_key)
   {
   if(const DH_PublicKey* dh_pub = dynamic_cast<const DH_PublicKey*>(state->kex_priv))
      {
      append_tls_length_value(m_params, BigInt::encode(dh_pub->get_domain().get_p()), 2);
      append_tls_length_value(m_params, BigInt::encode(dh_pub->get_domain().get_g()), 2);
      append_tls_length_value(m_params, dh_pub->public_value(), 2);
      }
   else
      throw Invalid_Argument("Unknown key type " + state->kex_priv->algo_name() +
                             " for TLS key exchange");

   std::pair<std::string, Signature_Format> format =
      state->choose_sig_format(private_key, m_hash_algo, m_sig_algo, false);

   PK_Signer signer(*private_key, format.first, format.second);

   signer.update(state->client_hello->random());
   signer.update(state->server_hello->random());
   signer.update(params());
   m_signature = signer.signature(rng);

   send(writer, state->hash);
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
* Deserialize a Server Key Exchange message
*/
Server_Key_Exchange::Server_Key_Exchange(const MemoryRegion<byte>& buf,
                                         const std::string& kex_algo,
                                         const std::string& sig_algo,
                                         Protocol_Version version)
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
   else
      throw Decoding_Error("Unsupported server key exchange type " + kex_algo);

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

}

}
