/*
* PKCS #5 PBES2
* (C) 1999-2008,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pbes2.h>
#include <botan/cipher_mode.h>
#include <botan/pbkdf.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/parsing.h>
#include <botan/alg_id.h>
#include <botan/oids.h>
#include <botan/rng.h>

namespace Botan {

namespace {

/*
* Encode PKCS#5 PBES2 parameters
*/
std::vector<uint8_t> encode_pbes2_params(const std::string& cipher,
                                      const std::string& prf,
                                      const secure_vector<uint8_t>& salt,
                                      const secure_vector<uint8_t>& iv,
                                      size_t iterations,
                                      size_t key_length)
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
      .encode(
         AlgorithmIdentifier("PKCS5.PBKDF2",
            DER_Encoder()
               .start_cons(SEQUENCE)
                  .encode(salt, OCTET_STRING)
                  .encode(iterations)
                  .encode(key_length)
                  .encode_if(
                     prf != "HMAC(SHA-160)",
                     AlgorithmIdentifier(prf, AlgorithmIdentifier::USE_NULL_PARAM))
               .end_cons()
            .get_contents_unlocked()
            )
         )
      .encode(
         AlgorithmIdentifier(cipher,
            DER_Encoder().encode(iv, OCTET_STRING).get_contents_unlocked()
            )
         )
      .end_cons()
      .get_contents_unlocked();
   }

/*
* PKCS#5 v2.0 PBE Encryption
*/
std::pair<AlgorithmIdentifier, std::vector<uint8_t>>
pbes2_encrypt_shared(const secure_vector<uint8_t>& key_bits,
                     const std::string& passphrase,
                     size_t* msec_in_iterations_out,
                     size_t iterations_if_msec_null,
                     const std::string& cipher,
                     const std::string& digest,
                     RandomNumberGenerator& rng)
   {
   const std::string prf = "HMAC(" + digest + ")";

   const std::vector<std::string> cipher_spec = split_on(cipher, '/');
   if(cipher_spec.size() != 2)
      throw Decoding_Error("PBE-PKCS5 v2.0: Invalid cipher spec " + cipher);

   const secure_vector<uint8_t> salt = rng.random_vec(12);

   if(cipher_spec[1] != "CBC" && cipher_spec[1] != "GCM")
      throw Decoding_Error("PBE-PKCS5 v2.0: Don't know param format for " + cipher);

   std::unique_ptr<Cipher_Mode> enc(get_cipher_mode(cipher, ENCRYPTION));

   if(!enc)
      throw Decoding_Error("PBE-PKCS5 cannot encrypt no cipher " + cipher);

   std::unique_ptr<PBKDF> pbkdf(get_pbkdf("PBKDF2(" + prf + ")"));

   const size_t key_length = enc->key_spec().maximum_keylength();


   secure_vector<uint8_t> iv = rng.random_vec(enc->default_nonce_length());

   size_t iterations = iterations_if_msec_null;

   if(msec_in_iterations_out)
      {
      std::chrono::milliseconds msec(*msec_in_iterations_out);
      enc->set_key(pbkdf->derive_key(key_length, passphrase, salt.data(), salt.size(), msec, iterations).bits_of());
      *msec_in_iterations_out = iterations;
      }
   else
      {
      enc->set_key(pbkdf->pbkdf_iterations(key_length, passphrase, salt.data(), salt.size(), iterations));
      }

   enc->start(iv);
   secure_vector<uint8_t> buf = key_bits;
   enc->finish(buf);

   AlgorithmIdentifier id(
      OIDS::lookup("PBE-PKCS5v20"),
      encode_pbes2_params(cipher, prf, salt, iv, iterations, key_length));

   return std::make_pair(id, unlock(buf));
   }


}

std::pair<AlgorithmIdentifier, std::vector<uint8_t>>
pbes2_encrypt(const secure_vector<uint8_t>& key_bits,
              const std::string& passphrase,
              std::chrono::milliseconds msec,
              const std::string& cipher,
              const std::string& digest,
              RandomNumberGenerator& rng)
   {
   size_t msec_in_iterations_out = static_cast<size_t>(msec.count());
   return pbes2_encrypt_shared(key_bits, passphrase, &msec_in_iterations_out, 0, cipher, digest, rng);
   // return value msec_in_iterations_out discarded
   }

std::pair<AlgorithmIdentifier, std::vector<uint8_t>>
pbes2_encrypt_msec(const secure_vector<uint8_t>& key_bits,
                   const std::string& passphrase,
                   std::chrono::milliseconds msec,
                   size_t* out_iterations_if_nonnull,
                   const std::string& cipher,
                   const std::string& digest,
                   RandomNumberGenerator& rng)
   {
   size_t msec_in_iterations_out = static_cast<size_t>(msec.count());

   auto ret = pbes2_encrypt_shared(key_bits, passphrase, &msec_in_iterations_out, 0, cipher, digest, rng);

   if(out_iterations_if_nonnull)
      *out_iterations_if_nonnull = msec_in_iterations_out;

   return ret;
   }

std::pair<AlgorithmIdentifier, std::vector<uint8_t>>
pbes2_encrypt_iter(const secure_vector<uint8_t>& key_bits,
                   const std::string& passphrase,
                   size_t pbkdf_iter,
                   const std::string& cipher,
                   const std::string& digest,
                   RandomNumberGenerator& rng)
   {
   return pbes2_encrypt_shared(key_bits, passphrase, nullptr, pbkdf_iter, cipher, digest, rng);
   }

secure_vector<uint8_t>
pbes2_decrypt(const secure_vector<uint8_t>& key_bits,
              const std::string& passphrase,
              const std::vector<uint8_t>& params)
   {
   AlgorithmIdentifier kdf_algo, enc_algo;

   BER_Decoder(params)
      .start_cons(SEQUENCE)
         .decode(kdf_algo)
         .decode(enc_algo)
      .end_cons();

   AlgorithmIdentifier prf_algo;

   if(kdf_algo.oid != OIDS::lookup("PKCS5.PBKDF2"))
      throw Decoding_Error("PBE-PKCS5 v2.0: Unknown KDF algorithm " +
                           kdf_algo.oid.as_string());

   secure_vector<uint8_t> salt;
   size_t iterations = 0, key_length = 0;

   BER_Decoder(kdf_algo.parameters)
      .start_cons(SEQUENCE)
         .decode(salt, OCTET_STRING)
         .decode(iterations)
         .decode_optional(key_length, INTEGER, UNIVERSAL)
         .decode_optional(prf_algo, SEQUENCE, CONSTRUCTED,
                          AlgorithmIdentifier("HMAC(SHA-160)",
                                              AlgorithmIdentifier::USE_NULL_PARAM))
      .end_cons();

   const std::string cipher = OIDS::lookup(enc_algo.oid);
   const std::vector<std::string> cipher_spec = split_on(cipher, '/');
   if(cipher_spec.size() != 2)
      throw Decoding_Error("PBE-PKCS5 v2.0: Invalid cipher spec " + cipher);
   if(cipher_spec[1] != "CBC" && cipher_spec[1] != "GCM")
      throw Decoding_Error("PBE-PKCS5 v2.0: Don't know param format for " + cipher);

   if(salt.size() < 8)
      throw Decoding_Error("PBE-PKCS5 v2.0: Encoded salt is too small");

   secure_vector<uint8_t> iv;
   BER_Decoder(enc_algo.parameters).decode(iv, OCTET_STRING).verify_end();

   const std::string prf = OIDS::lookup(prf_algo.oid);

   std::unique_ptr<PBKDF> pbkdf(get_pbkdf("PBKDF2(" + prf + ")"));

   std::unique_ptr<Cipher_Mode> dec(get_cipher_mode(cipher, DECRYPTION));
   if(!dec)
      throw Decoding_Error("PBE-PKCS5 cannot decrypt no cipher " + cipher);

   if(key_length == 0)
      key_length = dec->key_spec().maximum_keylength();

   dec->set_key(pbkdf->pbkdf_iterations(key_length, passphrase, salt.data(), salt.size(), iterations));

   dec->start(iv);

   secure_vector<uint8_t> buf = key_bits;
   dec->finish(buf);

   return buf;
   }

}
