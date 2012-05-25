/*
* Certificate Verify Message
* (C) 2004,2006,2011,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_extensions.h>
#include <botan/tls_record.h>
#include <botan/internal/assert.h>
#include <memory>

namespace Botan {

namespace TLS {

/*
* Create a new Certificate Verify message
*/
Certificate_Verify::Certificate_Verify(Record_Writer& writer,
                                       Handshake_State* state,
                                       RandomNumberGenerator& rng,
                                       const Private_Key* priv_key)
   {
   BOTAN_ASSERT_NONNULL(priv_key);

   std::pair<std::string, Signature_Format> format =
      state->choose_sig_format(priv_key, hash_algo, sig_algo, true);

   PK_Signer signer(*priv_key, format.first, format.second);

   if(state->version() == Protocol_Version::SSL_V3)
      {
      secure_vector<byte> md5_sha = state->hash.final_ssl3(
         state->keys.master_secret());

      if(priv_key->algo_name() == "DSA")
         signature = signer.sign_message(&md5_sha[16], md5_sha.size()-16, rng);
      else
         signature = signer.sign_message(md5_sha, rng);
      }
   else
      {
      signature = signer.sign_message(state->hash.get_contents(), rng);
      }

   state->hash.update(writer.send(*this));
   }

/*
* Deserialize a Certificate Verify message
*/
Certificate_Verify::Certificate_Verify(const std::vector<byte>& buf,
                                       Protocol_Version version)
   {
   TLS_Data_Reader reader(buf);

   if(version >= Protocol_Version::TLS_V12)
      {
      hash_algo = Signature_Algorithms::hash_algo_name(reader.get_byte());
      sig_algo = Signature_Algorithms::sig_algo_name(reader.get_byte());
      }

   signature = reader.get_range<byte>(2, 0, 65535);
   }

/*
* Serialize a Certificate Verify message
*/
std::vector<byte> Certificate_Verify::serialize() const
   {
   std::vector<byte> buf;

   if(hash_algo != "" && sig_algo != "")
      {
      buf.push_back(Signature_Algorithms::hash_algo_code(hash_algo));
      buf.push_back(Signature_Algorithms::sig_algo_code(sig_algo));
      }

   const u16bit sig_len = signature.size();
   buf.push_back(get_byte(0, sig_len));
   buf.push_back(get_byte(1, sig_len));
   buf += signature;

   return buf;
   }

/*
* Verify a Certificate Verify message
*/
bool Certificate_Verify::verify(const X509_Certificate& cert,
                                Handshake_State* state)
   {
   std::unique_ptr<Public_Key> key(cert.subject_public_key());

   std::pair<std::string, Signature_Format> format =
      state->understand_sig_format(key.get(), hash_algo, sig_algo, true);

   PK_Verifier verifier(*key, format.first, format.second);

   if(state->version() == Protocol_Version::SSL_V3)
      {
      secure_vector<byte> md5_sha = state->hash.final_ssl3(
         state->keys.master_secret());

      return verifier.verify_message(&md5_sha[16], md5_sha.size()-16,
                                     &signature[0], signature.size());
      }

   return verifier.verify_message(state->hash.get_contents(), signature);
   }

}

}
