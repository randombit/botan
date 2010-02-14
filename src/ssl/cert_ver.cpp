/**
* Certificate Verify Message Source File
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_messages.h>
#include <botan/look_pk.h>
#include <botan/rsa.h>
#include <botan/dsa.h>
#include <botan/loadstor.h>
#include <memory>

namespace Botan {

/**
* Create a new Certificate Verify message
*/
Certificate_Verify::Certificate_Verify(RandomNumberGenerator& rng,
                                       Record_Writer& writer,
                                       HandshakeHash& hash,
                                       const PKCS8_PrivateKey* priv_key)
   {
   const PK_Signing_Key* sign_key =
      dynamic_cast<const PK_Signing_Key*>(priv_key);

   if(sign_key)
      {
      PK_Signer* signer = 0;
      try
         {
         if(dynamic_cast<const RSA_PrivateKey*>(sign_key))
            signer = get_pk_signer(*sign_key, "EMSA3(TLS.Digest.0)");
         else if(dynamic_cast<const DSA_PrivateKey*>(sign_key))
            signer = get_pk_signer(*sign_key, "EMSA1(SHA-1)");
         else
            throw Invalid_Argument("Unknown PK algo for TLS signature");

         signature = signer->sign_message(hash.final(), rng);
         delete signer;
         }
      catch(...)
         {
         delete signer;
         throw;
         }

      send(writer, hash);
      }
   }

/**
* Serialize a Certificate Verify message
*/
SecureVector<byte> Certificate_Verify::serialize() const
   {
   SecureVector<byte> buf;

   u16bit sig_len = signature.size();
   buf.append(get_byte(0, sig_len));
   buf.append(get_byte(1, sig_len));
   buf.append(signature);

   return buf;
   }

/**
* Deserialize a Certificate Verify message
*/
void Certificate_Verify::deserialize(const MemoryRegion<byte>& buf)
   {
   if(buf.size() < 2)
      throw Decoding_Error("Certificate_Verify: Corrupted packet");

   u32bit sig_len = make_u16bit(buf[0], buf[1]);
   if(buf.size() != 2 + sig_len)
      throw Decoding_Error("Certificate_Verify: Corrupted packet");

   signature.set(buf + 2, sig_len);
   }

/**
* Verify a Certificate Verify message
*/
bool Certificate_Verify::verify(const X509_Certificate& cert,
                                HandshakeHash& hash)
   {
   // FIXME: duplicate of Server_Key_Exchange::verify

   std::auto_ptr<X509_PublicKey> key(cert.subject_public_key());

   DSA_PublicKey* dsa_pub = dynamic_cast<DSA_PublicKey*>(key.get());
   RSA_PublicKey* rsa_pub = dynamic_cast<RSA_PublicKey*>(key.get());

   std::auto_ptr<PK_Verifier> verifier;

   if(dsa_pub)
      verifier.reset(get_pk_verifier(*dsa_pub, "EMSA1(SHA-1)", DER_SEQUENCE));
   else if(rsa_pub)
      verifier.reset(get_pk_verifier(*rsa_pub, "EMSA3(TLS.Digest.0)"));
   else
      throw Invalid_Argument("Client did not provide a RSA/DSA cert");

   // FIXME: WRONG
   return verifier->verify_message(hash.final(), signature);
   }

}
