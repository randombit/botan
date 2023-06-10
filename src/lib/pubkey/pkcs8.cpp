/*
* PKCS #8
* (C) 1999-2010,2014,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pkcs8.h>

#include <botan/asn1_obj.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/pem.h>
#include <botan/pk_algs.h>
#include <botan/rng.h>
#include <botan/internal/fmt.h>
#include <botan/internal/scan_name.h>

#if defined(BOTAN_HAS_PKCS5_PBES2)
   #include <botan/internal/pbes2.h>
#endif

namespace Botan::PKCS8 {

namespace {

/*
* Get info from an EncryptedPrivateKeyInfo
*/
secure_vector<uint8_t> PKCS8_extract(DataSource& source, AlgorithmIdentifier& pbe_alg_id) {
   secure_vector<uint8_t> key_data;

   BER_Decoder(source).start_sequence().decode(pbe_alg_id).decode(key_data, ASN1_Type::OctetString).verify_end();

   return key_data;
}

/*
* PEM decode and/or decrypt a private key
*/
secure_vector<uint8_t> PKCS8_decode(DataSource& source,
                                    const std::function<std::string()>& get_passphrase,
                                    AlgorithmIdentifier& pk_alg_id,
                                    bool is_encrypted) {
   AlgorithmIdentifier pbe_alg_id;
   secure_vector<uint8_t> key_data, key;

   try {
      if(ASN1::maybe_BER(source) && !PEM_Code::matches(source)) {
         if(is_encrypted) {
            key_data = PKCS8_extract(source, pbe_alg_id);
         } else {
            // todo read more efficiently
            while(!source.end_of_data()) {
               uint8_t b;
               size_t read = source.read_byte(b);
               if(read) {
                  key_data.push_back(b);
               }
            }
         }
      } else {
         std::string label;
         key_data = PEM_Code::decode(source, label);

         // todo remove autodetect for pem as well?
         if(label == "PRIVATE KEY") {
            is_encrypted = false;
         } else if(label == "ENCRYPTED PRIVATE KEY") {
            DataSource_Memory key_source(key_data);
            key_data = PKCS8_extract(key_source, pbe_alg_id);
         } else {
            throw PKCS8_Exception(fmt("Unknown PEM label '{}'", label));
         }
      }

      if(key_data.empty()) {
         throw PKCS8_Exception("No key data found");
      }
   } catch(Decoding_Error& e) {
      throw Decoding_Error("PKCS #8 private key decoding", e);
   }

   try {
      if(is_encrypted) {
         if(pbe_alg_id.oid().to_formatted_string() != "PBE-PKCS5v20") {
            throw PKCS8_Exception(fmt("Unknown PBE type {}", pbe_alg_id.oid()));
         }

#if defined(BOTAN_HAS_PKCS5_PBES2)
         key = pbes2_decrypt(key_data, get_passphrase(), pbe_alg_id.parameters());
#else
         BOTAN_UNUSED(get_passphrase);
         throw Decoding_Error("Private key is encrypted but PBES2 was disabled in build");
#endif
      } else {
         key = key_data;
      }

      BER_Decoder(key)
         .start_sequence()
         .decode_and_check<size_t>(0, "Unknown PKCS #8 version number")
         .decode(pk_alg_id)
         .decode(key, ASN1_Type::OctetString)
         .discard_remaining()
         .end_cons();
   } catch(std::exception& e) {
      throw Decoding_Error("PKCS #8 private key decoding", e);
   }
   return key;
}

}  // namespace

/*
* PEM encode a PKCS #8 private key, unencrypted
*/
std::string PEM_encode(const Private_Key& key) {
   return PEM_Code::encode(key.private_key_info(), "PRIVATE KEY");
}

#if defined(BOTAN_HAS_PKCS5_PBES2)

namespace {

std::pair<std::string, std::string> choose_pbe_params(std::string_view pbe_algo, std::string_view key_algo) {
   if(pbe_algo.empty()) {
      /*
      * For algorithms where we are using a non-RFC format anyway, default to
      * SIV or GCM. For others (RSA, ECDSA, ...) default to something widely
      * compatible.
      */
      const bool nonstandard_pk = (key_algo == "McEliece" || key_algo == "XMSS");

      if(nonstandard_pk) {
   #if defined(BOTAN_HAS_AEAD_SIV) && defined(BOTAN_HAS_SHA2_64)
         return std::make_pair("AES-256/SIV", "SHA-512");
   #elif defined(BOTAN_HAS_AEAD_GCM) && defined(BOTAN_HAS_SHA2_64)
         return std::make_pair("AES-256/GCM", "SHA-512");
   #endif
      }

      // Default is something compatible with everyone else
      return std::make_pair("AES-256/CBC", "SHA-256");
   }

   SCAN_Name request(pbe_algo);

   if(request.arg_count() != 2 || (request.algo_name() != "PBE-PKCS5v20" && request.algo_name() != "PBES2")) {
      throw Invalid_Argument(fmt("Unsupported PBE '{}'", pbe_algo));
   }

   return std::make_pair(request.arg(0), request.arg(1));
}

}  // namespace

#endif

/*
* BER encode a PKCS #8 private key, encrypted
*/
std::vector<uint8_t> BER_encode(const Private_Key& key,
                                RandomNumberGenerator& rng,
                                std::string_view pass,
                                std::chrono::milliseconds msec,
                                std::string_view pbe_algo) {
#if defined(BOTAN_HAS_PKCS5_PBES2)
   const auto pbe_params = choose_pbe_params(pbe_algo, key.algo_name());

   const std::pair<AlgorithmIdentifier, std::vector<uint8_t>> pbe_info =
      pbes2_encrypt_msec(PKCS8::BER_encode(key), pass, msec, nullptr, pbe_params.first, pbe_params.second, rng);

   std::vector<uint8_t> output;
   DER_Encoder der(output);
   der.start_sequence().encode(pbe_info.first).encode(pbe_info.second, ASN1_Type::OctetString).end_cons();

   return output;
#else
   BOTAN_UNUSED(key, rng, pass, msec, pbe_algo);
   throw Encoding_Error("PKCS8::BER_encode cannot encrypt because PBES2 was disabled in build");
#endif
}

/*
* PEM encode a PKCS #8 private key, encrypted
*/
std::string PEM_encode(const Private_Key& key,
                       RandomNumberGenerator& rng,
                       std::string_view pass,
                       std::chrono::milliseconds msec,
                       std::string_view pbe_algo) {
   if(pass.empty()) {
      return PEM_encode(key);
   }

   return PEM_Code::encode(PKCS8::BER_encode(key, rng, pass, msec, pbe_algo), "ENCRYPTED PRIVATE KEY");
}

/*
* BER encode a PKCS #8 private key, encrypted
*/
std::vector<uint8_t> BER_encode_encrypted_pbkdf_iter(const Private_Key& key,
                                                     RandomNumberGenerator& rng,
                                                     std::string_view pass,
                                                     size_t pbkdf_iterations,
                                                     std::string_view cipher,
                                                     std::string_view pbkdf_hash) {
#if defined(BOTAN_HAS_PKCS5_PBES2)
   const std::pair<AlgorithmIdentifier, std::vector<uint8_t>> pbe_info =
      pbes2_encrypt_iter(key.private_key_info(),
                         pass,
                         pbkdf_iterations,
                         cipher.empty() ? "AES-256/CBC" : cipher,
                         pbkdf_hash.empty() ? "SHA-256" : pbkdf_hash,
                         rng);

   std::vector<uint8_t> output;
   DER_Encoder der(output);
   der.start_sequence().encode(pbe_info.first).encode(pbe_info.second, ASN1_Type::OctetString).end_cons();

   return output;

#else
   BOTAN_UNUSED(key, rng, pass, pbkdf_iterations, cipher, pbkdf_hash);
   throw Encoding_Error("PKCS8::BER_encode_encrypted_pbkdf_iter cannot encrypt because PBES2 disabled in build");
#endif
}

/*
* PEM encode a PKCS #8 private key, encrypted
*/
std::string PEM_encode_encrypted_pbkdf_iter(const Private_Key& key,
                                            RandomNumberGenerator& rng,
                                            std::string_view pass,
                                            size_t pbkdf_iterations,
                                            std::string_view cipher,
                                            std::string_view pbkdf_hash) {
   return PEM_Code::encode(PKCS8::BER_encode_encrypted_pbkdf_iter(key, rng, pass, pbkdf_iterations, cipher, pbkdf_hash),
                           "ENCRYPTED PRIVATE KEY");
}

/*
* BER encode a PKCS #8 private key, encrypted
*/
std::vector<uint8_t> BER_encode_encrypted_pbkdf_msec(const Private_Key& key,
                                                     RandomNumberGenerator& rng,
                                                     std::string_view pass,
                                                     std::chrono::milliseconds pbkdf_msec,
                                                     size_t* pbkdf_iterations,
                                                     std::string_view cipher,
                                                     std::string_view pbkdf_hash) {
#if defined(BOTAN_HAS_PKCS5_PBES2)
   const std::pair<AlgorithmIdentifier, std::vector<uint8_t>> pbe_info =
      pbes2_encrypt_msec(key.private_key_info(),
                         pass,
                         pbkdf_msec,
                         pbkdf_iterations,
                         cipher.empty() ? "AES-256/CBC" : cipher,
                         pbkdf_hash.empty() ? "SHA-256" : pbkdf_hash,
                         rng);

   std::vector<uint8_t> output;
   DER_Encoder(output)
      .start_sequence()
      .encode(pbe_info.first)
      .encode(pbe_info.second, ASN1_Type::OctetString)
      .end_cons();

   return output;
#else
   BOTAN_UNUSED(key, rng, pass, pbkdf_msec, pbkdf_iterations, cipher, pbkdf_hash);
   throw Encoding_Error("BER_encode_encrypted_pbkdf_msec cannot encrypt because PBES2 disabled in build");
#endif
}

/*
* PEM encode a PKCS #8 private key, encrypted
*/
std::string PEM_encode_encrypted_pbkdf_msec(const Private_Key& key,
                                            RandomNumberGenerator& rng,
                                            std::string_view pass,
                                            std::chrono::milliseconds pbkdf_msec,
                                            size_t* pbkdf_iterations,
                                            std::string_view cipher,
                                            std::string_view pbkdf_hash) {
   return PEM_Code::encode(
      PKCS8::BER_encode_encrypted_pbkdf_msec(key, rng, pass, pbkdf_msec, pbkdf_iterations, cipher, pbkdf_hash),
      "ENCRYPTED PRIVATE KEY");
}

namespace {

/*
* Extract a private key (encrypted/unencrypted) and return it
*/
std::unique_ptr<Private_Key> load_key(DataSource& source,
                                      const std::function<std::string()>& get_pass,
                                      bool is_encrypted) {
   AlgorithmIdentifier alg_id;
   secure_vector<uint8_t> pkcs8_key = PKCS8_decode(source, get_pass, alg_id, is_encrypted);

   const std::string alg_name = alg_id.oid().human_name_or_empty();
   if(alg_name.empty()) {
      throw PKCS8_Exception(fmt("Unknown algorithm OID {}", alg_id.oid()));
   }

   return load_private_key(alg_id, pkcs8_key);
}

}  // namespace

/*
* Extract an encrypted private key and return it
*/
std::unique_ptr<Private_Key> load_key(DataSource& source, const std::function<std::string()>& get_pass) {
   return load_key(source, get_pass, true);
}

std::unique_ptr<Private_Key> load_key(std::span<const uint8_t> source,
                                      const std::function<std::string()>& get_passphrase) {
   Botan::DataSource_Memory ds(source);
   return load_key(ds, get_passphrase);
}

std::unique_ptr<Private_Key> load_key(std::span<const uint8_t> source, std::string_view pass) {
   Botan::DataSource_Memory ds(source);
   return load_key(ds, pass);
}

std::unique_ptr<Private_Key> load_key(std::span<const uint8_t> source) {
   Botan::DataSource_Memory ds(source);
   return load_key(ds);
}

/*
* Extract an encrypted private key and return it
*/
std::unique_ptr<Private_Key> load_key(DataSource& source, std::string_view pass) {
   return load_key(
      source, [pass]() { return std::string(pass); }, true);
}

/*
* Extract an unencrypted private key and return it
*/
std::unique_ptr<Private_Key> load_key(DataSource& source) {
   auto fail_fn = []() -> std::string {
      throw PKCS8_Exception("Internal error: Attempt to read password for unencrypted key");
   };

   return load_key(source, fail_fn, false);
}

}  // namespace Botan::PKCS8
