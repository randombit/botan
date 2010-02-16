/**
* Client Key Exchange Message 
* (C) 2004-2008 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_messages.h>
#include <botan/dh.h>
#include <botan/rsa.h>
#include <botan/rng.h>
#include <botan/look_pk.h>
#include <botan/loadstor.h>
#include <memory>

namespace Botan {

/**
* Create a new Client Key Exchange message
*/
Client_Key_Exchange::Client_Key_Exchange(RandomNumberGenerator& rng,
                                         Record_Writer& writer,
                                         HandshakeHash& hash,
                                         const Public_Key* pub_key,
                                         Version_Code using_version,
                                         Version_Code pref_version)
   {
   const DH_PublicKey* dh_pub = dynamic_cast<const DH_PublicKey*>(pub_key);
   const RSA_PublicKey* rsa_pub = dynamic_cast<const RSA_PublicKey*>(pub_key);

   include_length = true;

   if(dh_pub)
      {
      DH_PrivateKey priv_key(rng, dh_pub->get_domain());
      pre_master = priv_key.derive_key(dh_pub->get_y());
      key_material = priv_key.public_value();
      }
   else if(rsa_pub)
      {
      pre_master.resize(48);
      rng.randomize(pre_master, 48);
      pre_master[0] = (pref_version >> 8) & 0xFF;
      pre_master[1] = (pref_version     ) & 0xFF;

      std::auto_ptr<PK_Encryptor> encryptor(get_pk_encryptor(*rsa_pub,
                                                             "PKCS1v15"));

      key_material = encryptor->encrypt(pre_master, rng);

      if(using_version == SSL_V3)
         include_length = false;
      }
   else
      throw Invalid_Argument("Client_Key_Exchange: Key not RSA or DH");

   send(writer, hash);
   }

/**
* Read a Client Key Exchange message
*/
Client_Key_Exchange::Client_Key_Exchange(const MemoryRegion<byte>& contents,
                                         const CipherSuite& suite,
                                         Version_Code using_version)
   {
   include_length = true;

   if(using_version == SSL_V3 &&
      (suite.kex_type() == CipherSuite::NO_KEX ||
       suite.kex_type() == CipherSuite::RSA_KEX))
      include_length = false;

   deserialize(contents);
   }

/**
* Serialize a Client Key Exchange message
*/
SecureVector<byte> Client_Key_Exchange::serialize() const
   {
   SecureVector<byte> buf;

   if(include_length)
      {
      u16bit key_size = key_material.size();
      buf.append(get_byte(0, key_size));
      buf.append(get_byte(1, key_size));
      }
   buf.append(key_material);

   return buf;
   }

/**
* Deserialize a Client Key Exchange message
*/
void Client_Key_Exchange::deserialize(const MemoryRegion<byte>& buf)
   {
   if(include_length)
      {
      if(buf.size() < 2)
         throw Decoding_Error("Client_Key_Exchange: Packet corrupted");

      u32bit size = make_u16bit(buf[0], buf[1]);
      if(size + 2 != buf.size())
         throw Decoding_Error("Client_Key_Exchange: Packet corrupted");

      key_material.set(buf + 2, size);
      }
   else
      key_material = buf;
   }

/**
* Return the pre_master_secret
*/
SecureVector<byte>
Client_Key_Exchange::pre_master_secret(RandomNumberGenerator& rng,
                                       const Private_Key* priv_key,
                                       Version_Code version)
   {
   const DH_PrivateKey* dh_priv = dynamic_cast<const DH_PrivateKey*>(priv_key);
   const RSA_PrivateKey* rsa_priv =
      dynamic_cast<const RSA_PrivateKey*>(priv_key);

   if(dh_priv)
      {
      try {
         pre_master = dh_priv->derive_key(key_material, key_material.size());
      }
      catch(std::exception& e)
         {
         pre_master.resize(dh_priv->public_value().size());
         rng.randomize(pre_master, pre_master.size());
         }

      return pre_master;
      }
   else if(rsa_priv)
      {
      std::auto_ptr<PK_Decryptor> decryptor(get_pk_decryptor(*rsa_priv,
                                                             "PKCS1v15"));

      try {
         pre_master = decryptor->decrypt(key_material);

         if(pre_master.size() != 48 ||
            make_u16bit(pre_master[0], pre_master[1]) != version)
            throw Decoding_Error("Client_Key_Exchange: Secret corrupted");
      }
      catch(std::exception)
         {
         pre_master.resize(48);
         rng.randomize(pre_master, pre_master.size());
         pre_master[0] = (version >> 8) & 0xFF;
         pre_master[1] = (version     ) & 0xFF;
         }

      return pre_master;
      }
   else
      throw Invalid_Argument("Client_Key_Exchange: Bad key for decrypt");
   }

/**
* Return the pre_master_secret
*/
SecureVector<byte> Client_Key_Exchange::pre_master_secret() const
   {
   return pre_master;
   }

}
