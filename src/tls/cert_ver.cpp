/*
* Certificate Verify Message
* (C) 2004,2006,2011,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/assert.h>
#include <botan/tls_exceptn.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <botan/dsa.h>
#include <botan/loadstor.h>
#include <memory>

namespace Botan {

/*
* Create a new Certificate Verify message
*/
Certificate_Verify::Certificate_Verify(Record_Writer& writer,
                                       TLS_Handshake_State* state,
                                       RandomNumberGenerator& rng,
                                       const Private_Key* priv_key)
   {
   BOTAN_ASSERT_NONNULL(priv_key);

   std::pair<std::string, Signature_Format> format =
      state->choose_sig_format(priv_key, true);

   PK_Signer signer(*priv_key, format.first, format.second);

   if(state->version == SSL_V3)
      {
      SecureVector<byte> md5_sha = state->hash.final_ssl3(
         state->keys.master_secret());

      if(priv_key->algo_name() == "DSA")
         signature = signer.sign_message(&md5_sha[16], md5_sha.size()-16, rng);
      else
         signature = signer.sign_message(md5_sha, rng);
      }
   else if(state->version == TLS_V10 || state->version == TLS_V11)
      {
      signature = signer.sign_message(state->hash.get_contents(), rng);
      }
   else
      throw TLS_Exception(PROTOCOL_VERSION,
                          "Unknown TLS version in certificate verification");

   send(writer, state->hash);
   }

/*
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

/*
* Deserialize a Certificate Verify message
*/
void Certificate_Verify::deserialize(const MemoryRegion<byte>& buf)
   {
   TLS_Data_Reader reader(buf);
   signature = reader.get_range<byte>(2, 0, 65535);
   }

/*
* Verify a Certificate Verify message
*/
bool Certificate_Verify::verify(const X509_Certificate& cert,
                                TLS_Handshake_State* state)
   {
   std::auto_ptr<Public_Key> key(cert.subject_public_key());

   std::pair<std::string, Signature_Format> format =
      state->choose_sig_format(key.get(), true);

   PK_Verifier verifier(*key, format.first, format.second);

   if(state->version == SSL_V3)
      {
      SecureVector<byte> md5_sha = state->hash.final_ssl3(
         state->keys.master_secret());

      return verifier.verify_message(&md5_sha[16], md5_sha.size()-16,
                                     &signature[0], signature.size());
      }
   else if(state->version == TLS_V10 || state->version == TLS_V11)
      {
      return verifier.verify_message(state->hash.get_contents(), signature);
      }
   else
      throw TLS_Exception(PROTOCOL_VERSION,
                          "Unknown TLS version in certificate verification");
   }

}
