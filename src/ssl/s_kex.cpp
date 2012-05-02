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
#include <botan/rsa.h>
#include <botan/dsa.h>
#include <botan/loadstor.h>
#include <memory>

namespace Botan {

/**
* Create a new Server Key Exchange message
*/
Server_Key_Exchange::Server_Key_Exchange(RandomNumberGenerator& rng,
                                         Record_Writer& writer,
                                         const Public_Key* kex_key,
                                         const Private_Key* priv_key,
                                         const MemoryRegion<byte>& c_random,
                                         const MemoryRegion<byte>& s_random,
                                         HandshakeHash& hash)
   {
   const DH_PublicKey* dh_pub = dynamic_cast<const DH_PublicKey*>(kex_key);
   const RSA_PublicKey* rsa_pub = dynamic_cast<const RSA_PublicKey*>(kex_key);

   if(dh_pub)
      {
      params.push_back(dh_pub->get_domain().get_p());
      params.push_back(dh_pub->get_domain().get_g());
      params.push_back(BigInt::decode(dh_pub->public_value()));
      }
   else if(rsa_pub)
      {
      params.push_back(rsa_pub->get_n());
      params.push_back(rsa_pub->get_e());
      }
   else
      throw Invalid_Argument("Bad key for TLS key exchange: not DH or RSA");


   std::string padding = "";
   Signature_Format format = IEEE_1363;

   if(priv_key->algo_name() == "RSA")
      padding = "EMSA3(TLS.Digest.0)";
   else if(priv_key->algo_name() == "DSA")
      {
      padding = "EMSA1(SHA-1)";
      format = DER_SEQUENCE;
      }
   else
      throw Invalid_Argument(priv_key->algo_name() +
                             " is invalid/unknown for TLS signatures");

   PK_Signer signer(*priv_key, padding, format);

   signer.update(c_random);
   signer.update(s_random);
   signer.update(serialize_params());
   signature = signer.signature(rng);

   send(writer, hash);
   }

/**
* Serialize a Server Key Exchange message
*/
SecureVector<byte> Server_Key_Exchange::serialize() const
   {
   SecureVector<byte> buf = serialize_params();
   append_tls_length_value(buf, signature, 2);
   return buf;
   }

/**
* Serialize the ServerParams structure
*/
SecureVector<byte> Server_Key_Exchange::serialize_params() const
   {
   SecureVector<byte> buf;

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

   SecureVector<byte> values[4];
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
   if(params.size() == 2)
      return new RSA_PublicKey(params[0], params[1]);
   else if(params.size() == 3)
      return new DH_PublicKey(DL_Group(params[0], params[1]), params[2]);
   else
      throw Internal_Error("Server_Key_Exchange::key: No key set");
   }

/**
* Verify a Server Key Exchange message
*/
bool Server_Key_Exchange::verify(const X509_Certificate& cert,
                                 const MemoryRegion<byte>& c_random,
                                 const MemoryRegion<byte>& s_random) const
   {

   std::auto_ptr<Public_Key> key(cert.subject_public_key());

   std::string padding = "";
   Signature_Format format = IEEE_1363;

   if(key->algo_name() == "RSA")
      padding = "EMSA3(TLS.Digest.0)";
   else if(key->algo_name() == "DSA")
      {
      padding = "EMSA1(SHA-1)";
      format = DER_SEQUENCE;
      }
   else
      throw Invalid_Argument(key->algo_name() +
                             " is invalid/unknown for TLS signatures");

   PK_Verifier verifier(*key, padding, format);

   SecureVector<byte> params_got = serialize_params();
   verifier.update(c_random);
   verifier.update(s_random);
   verifier.update(params_got);

   return verifier.check_signature(signature);
   }

}
