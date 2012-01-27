/*
* Client Key Exchange Message
* (C) 2004-2010 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_extensions.h>
#include <botan/internal/assert.h>
#include <botan/credentials_manager.h>
#include <botan/pubkey.h>
#include <botan/dh.h>
#include <botan/ecdh.h>
#include <botan/rsa.h>
#include <botan/rng.h>
#include <botan/loadstor.h>
#include <memory>

namespace Botan {

namespace TLS {

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
                                         Handshake_State* state,
                                         Credentials_Manager& creds,
                                         const std::vector<X509_Certificate>& peer_certs,
                                         RandomNumberGenerator& rng)
   {
   const std::string kex_algo = state->suite.kex_algo();

   if(kex_algo == "PSK")
      {
      std::string identity_hint = "";

      if(state->server_kex)
         {
         TLS_Data_Reader reader(state->server_kex->params());
         identity_hint = reader.get_string(2, 0, 65535);
         }

      const std::string hostname = state->client_hello->sni_hostname();

      const std::string psk_identity = creds.psk_identity("tls-client",
                                                          hostname,
                                                          identity_hint);

      append_tls_length_value(key_material, psk_identity, 2);

      SymmetricKey psk = creds.psk("tls-client", hostname, psk_identity);

      MemoryVector<byte> zeros(psk.length());

      append_tls_length_value(pre_master, zeros, 2);
      append_tls_length_value(pre_master, psk.bits_of(), 2);
      }
   else if(state->server_kex)
      {
      TLS_Data_Reader reader(state->server_kex->params());

      SymmetricKey psk;

      if(kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
         {
         std::string identity_hint = reader.get_string(2, 0, 65535);

         const std::string hostname = state->client_hello->sni_hostname();

         const std::string psk_identity = creds.psk_identity("tls-client",
                                                             hostname,
                                                             identity_hint);

         append_tls_length_value(key_material, psk_identity, 2);

         psk = creds.psk("tls-client", hostname, psk_identity);
         }

      if(kex_algo == "DH" || kex_algo == "DHE_PSK")
         {
         BigInt p = BigInt::decode(reader.get_range<byte>(2, 1, 65535));
         BigInt g = BigInt::decode(reader.get_range<byte>(2, 1, 65535));
         BigInt Y = BigInt::decode(reader.get_range<byte>(2, 1, 65535));

         if(reader.remaining_bytes())
            throw Decoding_Error("Bad params size for DH key exchange");

         DL_Group group(p, g);

         if(!group.verify_group(rng, true))
            throw Internal_Error("DH group failed validation, possible attack");

         DH_PublicKey counterparty_key(group, Y);

         // FIXME Check that public key is residue?

         DH_PrivateKey priv_key(rng, group);

         PK_Key_Agreement ka(priv_key, "Raw");

         SecureVector<byte> dh_secret = strip_leading_zeros(
            ka.derive_key(0, counterparty_key.public_value()).bits_of());

         if(kex_algo == "DH")
            pre_master = dh_secret;
         else
            {
            append_tls_length_value(pre_master, dh_secret, 2);
            append_tls_length_value(pre_master, psk.bits_of(), 2);
            }

         append_tls_length_value(key_material, priv_key.public_value(), 2);
         }
      else if(kex_algo == "ECDH" || kex_algo == "ECDHE_PSK")
         {
         const byte curve_type = reader.get_byte();

         if(curve_type != 3)
            throw Decoding_Error("Server sent non-named ECC curve");

         const u16bit curve_id = reader.get_u16bit();

         const std::string name = Supported_Elliptic_Curves::curve_id_to_name(curve_id);

         if(name == "")
            throw Decoding_Error("Server sent unknown named curve " + to_string(curve_id));

         EC_Group group(name);

         MemoryVector<byte> ecdh_key = reader.get_range<byte>(1, 1, 255);

         ECDH_PublicKey counterparty_key(group, OS2ECP(ecdh_key, group.get_curve()));

         ECDH_PrivateKey priv_key(rng, group);

         PK_Key_Agreement ka(priv_key, "Raw");

         SecureVector<byte> ecdh_secret = ka.derive_key(0, counterparty_key.public_value()).bits_of();

         if(kex_algo == "ECDH")
            pre_master = ecdh_secret;
         else
            {
            append_tls_length_value(pre_master, ecdh_secret, 2);
            append_tls_length_value(pre_master, psk.bits_of(), 2);
            }

         append_tls_length_value(key_material, priv_key.public_value(), 1);
         }
      else
         {
         throw Internal_Error("Client_Key_Exchange: Unknown kex " +
                              kex_algo);
         }
      }
   else
      {
      // No server key exchange msg better mean RSA kex + RSA key in cert

      if(kex_algo != "RSA")
         throw Unexpected_Message("No server kex but negotiated kex " + kex_algo);

      if(peer_certs.empty())
         throw Internal_Error("No certificate and no server key exchange");

      std::auto_ptr<Public_Key> pub_key(peer_certs[0].subject_public_key());

      if(const RSA_PublicKey* rsa_pub = dynamic_cast<const RSA_PublicKey*>(pub_key.get()))
         {
         const Protocol_Version pref_version = state->client_hello->version();

         pre_master = rng.random_vec(48);
         pre_master[0] = pref_version.major_version();
         pre_master[1] = pref_version.minor_version();

         PK_Encryptor_EME encryptor(*rsa_pub, "PKCS1v15");

         MemoryVector<byte> encrypted_key = encryptor.encrypt(pre_master, rng);

         if(state->version == Protocol_Version::SSL_V3)
            key_material = encrypted_key; // no length field
         else
            append_tls_length_value(key_material, encrypted_key, 2);
         }
      else
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Expected a RSA key in server cert but got " +
                             pub_key->algo_name());
      }

   send(writer, state->hash);
   }

/*
* Read a Client Key Exchange message
*/
Client_Key_Exchange::Client_Key_Exchange(const MemoryRegion<byte>& contents,
                                         const Handshake_State* state,
                                         Credentials_Manager& creds,
                                         const Policy& policy,
                                         RandomNumberGenerator& rng)
   {
   const std::string kex_algo = state->suite.kex_algo();

   if(kex_algo == "RSA")
      {
      BOTAN_ASSERT(state->server_certs && !state->server_certs->cert_chain().empty(),
                   "No server certificate to use for RSA");

      const Private_Key* private_key = state->server_rsa_kex_key;

      if(!private_key)
         throw Internal_Error("Expected RSA kex but no server kex key set");

      if(!dynamic_cast<const RSA_PrivateKey*>(private_key))
         throw Internal_Error("Expected RSA key but got " + private_key->algo_name());

      PK_Decryptor_EME decryptor(*private_key, "PKCS1v15");

      Protocol_Version client_version = state->client_hello->version();

      try
         {
         if(state->version == Protocol_Version::SSL_V3)
            {
            pre_master = decryptor.decrypt(contents);
            }
         else
            {
            TLS_Data_Reader reader(contents);
            pre_master = decryptor.decrypt(reader.get_range<byte>(2, 0, 65535));
            }

         if(pre_master.size() != 48 ||
            client_version.major_version() != pre_master[0] ||
            client_version.minor_version() != pre_master[1])
            {
            throw Decoding_Error("Client_Key_Exchange: Secret corrupted");
            }
         }
      catch(...)
         {
         // Randomize the hide timing channel
         pre_master = rng.random_vec(48);
         pre_master[0] = client_version.major_version();
         pre_master[1] = client_version.minor_version();
         }
      }
   else
      {
      TLS_Data_Reader reader(contents);

      SymmetricKey psk;

      if(kex_algo == "PSK" || kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
         {
         const std::string psk_identity = reader.get_string(2, 0, 65535);

         psk = creds.psk("tls-server",
                         state->client_hello->sni_hostname(),
                         psk_identity);

         if(psk.length() == 0)
            {
            if(policy.hide_unknown_users())
               throw TLS_Exception(Alert::UNKNOWN_PSK_IDENTITY,
                                   "No PSK for identifier " + psk_identity);
            else
               psk = SymmetricKey(rng, 16);
            }

         }

      if(kex_algo == "PSK")
         {
         MemoryVector<byte> zeros(psk.length());
         append_tls_length_value(pre_master, zeros, 2);
         append_tls_length_value(pre_master, psk.bits_of(), 2);
         }
      else if(kex_algo == "DH" || kex_algo == "DHE_PSK" ||
              kex_algo == "ECDH" || kex_algo == "ECDHE_PSK")
         {
         const Private_Key& private_key = state->server_kex->server_kex_key();

         const PK_Key_Agreement_Key* ka_key =
            dynamic_cast<const PK_Key_Agreement_Key*>(&private_key);

         if(!ka_key)
            throw Internal_Error("Expected key agreement key type but got " +
                                 private_key.algo_name());

         try
            {
            PK_Key_Agreement ka(*ka_key, "Raw");

            MemoryVector<byte> client_pubkey;

            if(ka_key->algo_name() == "DH")
               client_pubkey = reader.get_range<byte>(2, 0, 65535);
            else
               client_pubkey = reader.get_range<byte>(1, 0, 255);

            SecureVector<byte> shared_secret = ka.derive_key(0, client_pubkey).bits_of();

            if(ka_key->algo_name() == "DH")
               shared_secret = strip_leading_zeros(shared_secret);

            if(kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
               {
               append_tls_length_value(pre_master, shared_secret, 2);
               append_tls_length_value(pre_master, psk.bits_of(), 2);
               }
            else
               pre_master = shared_secret;
            }
         catch(std::exception &e)
            {
            /*
            * Something failed in the DH computation. To avoid possible
            * timing attacks, randomize the pre-master output and carry
            * on, allowing the protocol to fail later in the finished
            * checks.
            */
            pre_master = rng.random_vec(ka_key->public_value().size());
            }
         }
      else
         throw Internal_Error("Client_Key_Exchange: Unknown kex type " + kex_algo);
      }
   }

}

}
