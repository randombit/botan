/*
* Server Key Exchange Message
* (C) 2004-2010,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_extensions.h>
#include <botan/pubkey.h>
#include <botan/dh.h>
#include <botan/loadstor.h>
#include <memory>

namespace Botan {

/**
* Create a new Server Key Exchange message
*/
Server_Key_Exchange::Server_Key_Exchange(Record_Writer& writer,
                                         TLS_Handshake_State* state,
                                         RandomNumberGenerator& rng,
                                         const Private_Key* private_key)
   {
   const DH_PublicKey* dh_pub = dynamic_cast<const DH_PublicKey*>(state->kex_priv);

   if(dh_pub)
      {
      m_params.push_back(dh_pub->get_domain().get_p());
      m_params.push_back(dh_pub->get_domain().get_g());
      m_params.push_back(BigInt::decode(dh_pub->public_value()));
      }
   else
      throw Invalid_Argument("Unknown key type " + state->kex_priv->algo_name() +
                             " for TLS key exchange");

   std::pair<std::string, Signature_Format> format =
      state->choose_sig_format(private_key, m_hash_algo, m_sig_algo, false);

   PK_Signer signer(*private_key, format.first, format.second);

   signer.update(state->client_hello->random());
   signer.update(state->server_hello->random());
   signer.update(serialize_params());
   m_signature = signer.signature(rng);

   send(writer, state->hash);
   }

/**
* Serialize a Server Key Exchange message
*/
MemoryVector<byte> Server_Key_Exchange::serialize() const
   {
   MemoryVector<byte> buf = serialize_params();

   // NEEDS VERSION CHECK
   if(m_hash_algo != "" && m_sig_algo != "")
      {
      buf.push_back(Signature_Algorithms::hash_algo_code(m_hash_algo));
      buf.push_back(Signature_Algorithms::sig_algo_code(m_sig_algo));
      }

   append_tls_length_value(buf, m_signature, 2);
   return buf;
   }

/**
* Serialize the ServerParams structure
*/
MemoryVector<byte> Server_Key_Exchange::serialize_params() const
   {
   MemoryVector<byte> buf;

   for(size_t i = 0; i != m_params.size(); ++i)
      append_tls_length_value(buf, BigInt::encode(m_params[i]), 2);

   return buf;
   }

/**
* Deserialize a Server Key Exchange message
*/
Server_Key_Exchange::Server_Key_Exchange(const MemoryRegion<byte>& buf,
                                         const std::string& kex_algo,
                                         const std::string& sig_algo,
                                         Version_Code version)
   {
   if(buf.size() < 6)
      throw Decoding_Error("Server_Key_Exchange: Packet corrupted");

   TLS_Data_Reader reader(buf);

   if(kex_algo == "DH")
      {
      // 3 bigints, DH p, g, Y

      for(size_t i = 0; i != 3; ++i)
         {
         BigInt v = BigInt::decode(reader.get_range<byte>(2, 1, 65535));
         m_params.push_back(v);
         }
      }
   else
      throw Decoding_Error("Unsupported server key exchange type " + kex_algo);

   if(sig_algo != "")
      {
      if(version >= TLS_V12)
         {
         m_hash_algo = Signature_Algorithms::hash_algo_name(reader.get_byte());
         m_sig_algo = Signature_Algorithms::sig_algo_name(reader.get_byte());
         }

      m_signature = reader.get_range<byte>(2, 0, 65535);
      }
   }

/**
* Return the public key
*/
Public_Key* Server_Key_Exchange::key() const
   {
   if(m_params.size() == 3)
      return new DH_PublicKey(DL_Group(m_params[0], m_params[1]), m_params[2]);
   else
      throw Internal_Error("Server_Key_Exchange::key: No key set");
   }

/**
* Verify a Server Key Exchange message
*/
bool Server_Key_Exchange::verify(const X509_Certificate& cert,
                                 TLS_Handshake_State* state) const
   {
   std::auto_ptr<Public_Key> key(cert.subject_public_key());

   std::pair<std::string, Signature_Format> format =
      state->choose_sig_format(key.get(), m_hash_algo, m_sig_algo, false);

   PK_Verifier verifier(*key, format.first, format.second);

   verifier.update(state->client_hello->random());
   verifier.update(state->server_hello->random());
   verifier.update(serialize_params());

   return verifier.check_signature(m_signature);
   }

}
