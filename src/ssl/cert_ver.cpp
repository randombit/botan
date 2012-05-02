/*
* Certificate Verify Message
* (C) 2004-2010 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_reader.h>
#include <botan/pubkey.h>
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
                                       const Private_Key* priv_key)
   {
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

   signature = signer.sign_message(hash.final(), rng);
   send(writer, hash);
   }

/**
* Serialize a Certificate Verify message
*/
SecureVector<byte> Certificate_Verify::serialize() const
   {
   SecureVector<byte> buf;

   const u16bit sig_len = signature.size();
   buf.push_back(get_byte(0, sig_len));
   buf.push_back(get_byte(1, sig_len));
   buf += signature;

   return buf;
   }

/**
* Deserialize a Certificate Verify message
*/
void Certificate_Verify::deserialize(const MemoryRegion<byte>& buf)
   {
   TLS_Data_Reader reader(buf);
   signature = reader.get_range<byte>(2, 0, 65535);
   }

/**
* Verify a Certificate Verify message
*/
bool Certificate_Verify::verify(const X509_Certificate& cert,
                                HandshakeHash& hash)
   {
   // FIXME: duplicate of Server_Key_Exchange::verify

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
   return verifier.verify_message(hash.final(), signature);
   }

}
