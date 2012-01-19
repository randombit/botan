/*
* Server Key Exchange Message
* (C) 2004-2010 Jack Lloyd
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
      params.push_back(dh_pub->get_domain().get_p());
      params.push_back(dh_pub->get_domain().get_g());
      params.push_back(BigInt::decode(dh_pub->public_value()));
      }
   else
      throw Invalid_Argument("Unknown key type " + state->kex_priv->algo_name() +
                             " for TLS key exchange");

   // FIXME: this should respect client's hash preferences
   if(state->version >= TLS_V12)
      {
      hash_algo = TLS_ALGO_HASH_SHA256;
      sig_algo = TLS_ALGO_SIGNER_RSA;
      }
   else
      {
      hash_algo = TLS_ALGO_NONE;
      sig_algo = TLS_ALGO_NONE;
      }

   std::pair<std::string, Signature_Format> format =
      state->choose_sig_format(private_key, hash_algo, false);

   PK_Signer signer(*private_key, format.first, format.second);

   signer.update(state->client_hello->random());
   signer.update(state->server_hello->random());
   signer.update(serialize_params());
   signature = signer.signature(rng);

   send(writer, state->hash);
   }

/**
* Serialize a Server Key Exchange message
*/
MemoryVector<byte> Server_Key_Exchange::serialize() const
   {
   MemoryVector<byte> buf = serialize_params();

   if(hash_algo != TLS_ALGO_NONE)
      {
      buf.push_back(Signature_Algorithms::hash_algo_code(hash_algo));
      buf.push_back(Signature_Algorithms::sig_algo_code(sig_algo));
      }

   append_tls_length_value(buf, signature, 2);
   return buf;
   }

/**
* Serialize the ServerParams structure
*/
MemoryVector<byte> Server_Key_Exchange::serialize_params() const
   {
   MemoryVector<byte> buf;

   for(size_t i = 0; i != params.size(); ++i)
      append_tls_length_value(buf, BigInt::encode(params[i]), 2);

   return buf;
   }

/**
* Deserialize a Server Key Exchange message
*/
Server_Key_Exchange::Server_Key_Exchange(const MemoryRegion<byte>& buf,
                                         TLS_Ciphersuite_Algos kex_alg,
                                         TLS_Ciphersuite_Algos sig_alg,
                                         Version_Code version)
   {
   if(buf.size() < 6)
      throw Decoding_Error("Server_Key_Exchange: Packet corrupted");

   TLS_Data_Reader reader(buf);

   if(kex_alg == TLS_ALGO_KEYEXCH_DH)
      {
      // 3 bigints, DH p, g, Y

      for(size_t i = 0; i != 3; ++i)
         {
         BigInt v = BigInt::decode(reader.get_range<byte>(2, 1, 65535));
         params.push_back(v);
         }
      }
   else
      throw Decoding_Error("Unsupported server key exchange type");

   if(sig_alg != TLS_ALGO_SIGNER_ANON)
      {
      if(version < TLS_V12)
         {
         // use old defaults
         hash_algo = TLS_ALGO_NONE;
         sig_algo = TLS_ALGO_NONE;
         }
      else
         {
         hash_algo = Signature_Algorithms::hash_algo_code(reader.get_byte());
         sig_algo = Signature_Algorithms::sig_algo_code(reader.get_byte());
         }

      signature = reader.get_range<byte>(2, 0, 65535);
      }
   }

/**
* Return the public key
*/
Public_Key* Server_Key_Exchange::key() const
   {
   if(params.size() == 3)
      return new DH_PublicKey(DL_Group(params[0], params[1]), params[2]);
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

   printf("Checking %s vs code %d\n", key->algo_name().c_str(), sig_algo);

   std::pair<std::string, Signature_Format> format =
      state->choose_sig_format(key.get(), hash_algo, false);

   PK_Verifier verifier(*key, format.first, format.second);

   verifier.update(state->client_hello->random());
   verifier.update(state->server_hello->random());
   verifier.update(serialize_params());

   return verifier.check_signature(signature);
   }

}
