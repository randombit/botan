/*
* Client Key Exchange Message
* (C) 2004-2010 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_reader.h>
#include <botan/pubkey.h>
#include <botan/dh.h>
#include <botan/rsa.h>
#include <botan/rng.h>
#include <botan/loadstor.h>
#include <memory>

namespace Botan {

namespace {

SecureVector<byte> strip_leading_zeros(const MemoryRegion<byte>& input)
   {
   size_t leading_zeros = 0;

   for(size_t i = 0; i != input.size(); ++i)
      {
      if(input[i] != 0)
         break;
      ++leading_zeros;
      }

   SecureVector<byte> output(&input[leading_zeros],
                             input.size() - leading_zeros);
   return output;
   }

}

/*
* Create a new Client Key Exchange message
*/
Client_Key_Exchange::Client_Key_Exchange(Record_Writer& writer,
                                         TLS_Handshake_State* state,
                                         const std::vector<X509_Certificate>& peer_certs,
                                         RandomNumberGenerator& rng)
   {
   include_length = true;

   if(state->server_kex)
      {
      std::auto_ptr<Public_Key> pub_key(state->server_kex->key());

      if(pub_key->algo_name() != state->suite.kex_algo())
         throw TLS_Exception(HANDSHAKE_FAILURE,
                             "Server sent a " + pub_key->algo_name() +
                             " key but we expected " + state->suite.kex_algo());

      if(const DH_PublicKey* dh_pub = dynamic_cast<const DH_PublicKey*>(pub_key.get()))
         {
         DH_PrivateKey priv_key(rng, dh_pub->get_domain());

         PK_Key_Agreement ka(priv_key, "Raw");

         pre_master = strip_leading_zeros(
            ka.derive_key(0, dh_pub->public_value()).bits_of());

         key_material = priv_key.public_value();
         }
      else
         throw Internal_Error("Server key exchange not a known key type");
      }
   else
      {
      // No server key exchange msg better mean a RSA key in the cert

      std::auto_ptr<Public_Key> pub_key(peer_certs[0].subject_public_key());

      if(peer_certs.empty())
         throw Internal_Error("No certificate and no server key exchange");

      if(const RSA_PublicKey* rsa_pub = dynamic_cast<const RSA_PublicKey*>(pub_key.get()))
         {
         const Version_Code pref_version = state->client_hello->version();

         pre_master = rng.random_vec(48);
         pre_master[0] = (pref_version >> 8) & 0xFF;
         pre_master[1] = (pref_version     ) & 0xFF;

         PK_Encryptor_EME encryptor(*rsa_pub, "PKCS1v15");

         key_material = encryptor.encrypt(pre_master, rng);

         if(state->version == SSL_V3)
            include_length = false;
         }
      else
         throw TLS_Exception(HANDSHAKE_FAILURE,
                             "Expected a RSA key in server cert but got " +
                             pub_key->algo_name());
      }

   send(writer, state->hash);
   }

/*
* Read a Client Key Exchange message
*/
Client_Key_Exchange::Client_Key_Exchange(const MemoryRegion<byte>& contents,
                                         const TLS_Ciphersuite& suite,
                                         Version_Code using_version)
   {
   include_length = true;

   if(using_version == SSL_V3 && (suite.kex_algo() == ""))
      include_length = false;

   if(include_length)
      {
      TLS_Data_Reader reader(contents);
      key_material = reader.get_range<byte>(2, 0, 65535);
      }
   else
      key_material = contents;
   }

/*
* Serialize a Client Key Exchange message
*/
MemoryVector<byte> Client_Key_Exchange::serialize() const
   {
   if(include_length)
      {
      MemoryVector<byte> buf;
      append_tls_length_value(buf, key_material, 2);
      return buf;
      }
   else
      return key_material;
   }

/*
* Return the pre_master_secret
*/
SecureVector<byte>
Client_Key_Exchange::pre_master_secret(RandomNumberGenerator& rng,
                                       const Private_Key* priv_key,
                                       Version_Code version)
   {

   if(const DH_PrivateKey* dh_priv = dynamic_cast<const DH_PrivateKey*>(priv_key))
      {
      try {
         PK_Key_Agreement ka(*dh_priv, "Raw");

         pre_master = strip_leading_zeros(ka.derive_key(0, key_material).bits_of());
      }
      catch(...)
         {
         /*
         * Something failed in the DH computation. To avoid possible
         * timing attacks, randomize the pre-master output and carry
         * on, allowing the protocol to fail later in the finished
         * checks.
         */
         pre_master = rng.random_vec(dh_priv->public_value().size());
         }

      return pre_master;
      }
   else if(const RSA_PrivateKey* rsa_priv = dynamic_cast<const RSA_PrivateKey*>(priv_key))
      {
      PK_Decryptor_EME decryptor(*rsa_priv, "PKCS1v15");

      try {
         pre_master = decryptor.decrypt(key_material);

         if(pre_master.size() != 48 ||
            make_u16bit(pre_master[0], pre_master[1]) != version)
            throw Decoding_Error("Client_Key_Exchange: Secret corrupted");
      }
      catch(...)
         {
         pre_master = rng.random_vec(48);
         pre_master[0] = (version >> 8) & 0xFF;
         pre_master[1] = (version     ) & 0xFF;
         }

      return pre_master;
      }
   else
      throw Invalid_Argument("Client_Key_Exchange: Bad key for decrypt");
   }

}
