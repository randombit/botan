/**
* Server Key Exchange Message
* (C) 2004-2010 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_messages.h>
#include <botan/dh.h>
#include <botan/rsa.h>
#include <botan/dsa.h>
#include <botan/look_pk.h>
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

   std::auto_ptr<PK_Signer> signer;

   if(const RSA_PrivateKey* rsa = dynamic_cast<const RSA_PrivateKey*>(priv_key))
      {
      signer.reset(get_pk_signer(*rsa, "EMSA3(TLS.Digest.0)"));
      }
   else if(const DSA_PrivateKey* dsa =
           dynamic_cast<const DSA_PrivateKey*>(priv_key))
      {
      signer.reset(get_pk_signer(*dsa, "EMSA1(SHA-1)"));
      signer->set_output_format(DER_SEQUENCE);
      }
   else
      throw Invalid_Argument("Bad key for TLS signature: not RSA or DSA");

   signer->update(c_random);
   signer->update(s_random);
   signer->update(serialize_params());
   signature = signer->signature(rng);

   send(writer, hash);
   }

/**
* Serialize a Server Key Exchange message
*/
SecureVector<byte> Server_Key_Exchange::serialize() const
   {
   SecureVector<byte> buf = serialize_params();
   u16bit sig_len = signature.size();
   buf.append(get_byte(0, sig_len));
   buf.append(get_byte(1, sig_len));
   buf.append(signature);
   return buf;
   }

/**
* Serialize the ServerParams structure
*/
SecureVector<byte> Server_Key_Exchange::serialize_params() const
   {
   SecureVector<byte> buf;
   for(u32bit j = 0; j != params.size(); j++)
      {
      SecureVector<byte> param = BigInt::encode(params[j]);
      u16bit param_size = param.size();

      buf.append(get_byte(0, param_size));
      buf.append(get_byte(1, param_size));
      buf.append(param);
      }
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
   u32bit so_far = 0;

   for(u32bit j = 0; j != 4; j++)
      {
      u16bit len = make_u16bit(buf[so_far], buf[so_far+1]);
      so_far += 2;

      if(len + so_far > buf.size())
         throw Decoding_Error("Server_Key_Exchange: Packet corrupted");

      values[j].set(buf + so_far, len);
      so_far += len;

      if(j == 2 && so_far == buf.size())
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

   DSA_PublicKey* dsa_pub = dynamic_cast<DSA_PublicKey*>(key.get());
   RSA_PublicKey* rsa_pub = dynamic_cast<RSA_PublicKey*>(key.get());

   std::auto_ptr<PK_Verifier> verifier;

   if(dsa_pub)
      {
      verifier.reset(get_pk_verifier(*dsa_pub, "EMSA1(SHA-1)", DER_SEQUENCE));
      verifier->set_input_format(DER_SEQUENCE);
      }
   else if(rsa_pub)
      verifier.reset(get_pk_verifier(*rsa_pub, "EMSA3(TLS.Digest.0)"));
   else
      throw Invalid_Argument("Server did not provide a RSA/DSA cert");

   SecureVector<byte> params_got = serialize_params();
   verifier->update(c_random);
   verifier->update(s_random);
   verifier->update(params_got);

   return verifier->check_signature(signature, signature.size());
   }

}
