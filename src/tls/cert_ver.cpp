/*
* Certificate Verify Message
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_reader.h>
#include <botan/tls_exceptn.h>
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
                                       TLS_Handshake_Hash& hash,
                                       const Private_Key* priv_key)
   {
   std::string padding = "";
   Signature_Format format = IEEE_1363;

   if(priv_key->algo_name() == "RSA")
      padding = "EMSA3(TLS.Digest.0)";
   else if(priv_key->algo_name() == "DSA")
      {
      padding == "EMSA1(SHA-1)";
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
MemoryVector<byte> Certificate_Verify::serialize() const
   {
   MemoryVector<byte> buf;

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
                                TLS_Handshake_Hash& hash,
                                Version_Code version,
                                const SecureVector<byte>& master_secret)
   {
   // FIXME: duplicate of Server_Key_Exchange::verify

   std::auto_ptr<Public_Key> key(cert.subject_public_key());

   std::string padding = "";
   Signature_Format format = IEEE_1363;

   if(key->algo_name() == "RSA")
      padding = "EMSA3(TLS.Digest.0)";
   else if(key->algo_name() == "DSA")
      {
      if(version == SSL_V3)
         padding = "Raw";
      else
         padding = "EMSA1(SHA-1)";
      format = DER_SEQUENCE;
      }
   else
      throw Invalid_Argument(key->algo_name() +
                             " is invalid/unknown for TLS signatures");

   PK_Verifier verifier(*key, padding, format);

   if(version == SSL_V3)
      {
      SecureVector<byte> md5_sha = hash.final_ssl3(master_secret);

      return verifier.verify_message(&md5_sha[16], md5_sha.size()-16,
                                     &signature[0], signature.size());
      }
   else if(version == TLS_V10 || version == TLS_V11)
      return verifier.verify_message(hash.get_contents(), signature);
   else
      throw TLS_Exception(PROTOCOL_VERSION,
                          "Unknown TLS version in certificate verification");
   }

}
