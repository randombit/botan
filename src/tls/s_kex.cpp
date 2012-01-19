/*
* Server Key Exchange Message
* (C) 2004-2010 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_reader.h>
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

   std::pair<std::string, Signature_Format> format =
      state->choose_sig_format(private_key, false);

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
void Server_Key_Exchange::deserialize(const MemoryRegion<byte>& buf)
   {
   if(buf.size() < 6)
      throw Decoding_Error("Server_Key_Exchange: Packet corrupted");

   MemoryVector<byte> values[4];
   size_t so_far = 0;

   for(size_t i = 0; i != 4; ++i)
      {
      const u16bit len = make_u16bit(buf[so_far], buf[so_far+1]);
      so_far += 2;

      if(len + so_far > buf.size())
         throw Decoding_Error("Server_Key_Exchange: Packet corrupted");

      values[i].resize(len);
      copy_mem(&values[i][0], &buf[so_far], len);
      so_far += len;

      if(i == 2 && so_far == buf.size())
         break;
      }

   params.push_back(BigInt::decode(values[0]));
   params.push_back(BigInt::decode(values[1]));
   if(values[3].size())
      {
      params.push_back(BigInt::decode(values[2]));
      signature = values[3];
      }
   else
      signature = values[2];
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

   std::pair<std::string, Signature_Format> format =
      state->choose_sig_format(key.get(), false);

   PK_Verifier verifier(*key, format.first, format.second);

   verifier.update(state->client_hello->random());
   verifier.update(state->server_hello->random());
   verifier.update(serialize_params());

   return verifier.check_signature(signature);
   }

}
