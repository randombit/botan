/*
* PKCS #8
* (C) 1999-2010,2014,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pkcs8.h>

#include <botan/asn1_obj.h>
#include <botan/assert.h>
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
   secure_vector<uint8_t> key_data;
   secure_vector<uint8_t> key;

   try {
      if(ASN1::maybe_BER(source) && !PEM_Code::matches(source)) {
         if(is_encrypted) {
            key_data = PKCS8_extract(source, pbe_alg_id);
         } else {
            // todo read more efficiently
            while(auto b = source.read_byte()) {
               key_data.push_back(*b);
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

std::string EncryptedPrivateKey::as_pem() const {
   return PEM_Code::encode(m_pkcs8, "ENCRYPTED PRIVATE KEY");
}

KeyEncryptionOptions::KeyEncryptionOptions(std::chrono::milliseconds pwhash_duration) :
      KeyEncryptionOptions(default_cipher(), default_pwhash(), pwhash_duration) {}

KeyEncryptionOptions KeyEncryptionOptions::defaults() {
   return KeyEncryptionOptions(default_cipher(), default_pwhash(), default_pwhash_duration());
}

size_t KeyEncryptionOptions::pwhash_iterations() const {
   BOTAN_STATE_CHECK(m_pwhash_iterations.has_value());
   return m_pwhash_iterations.value();
}

std::chrono::milliseconds KeyEncryptionOptions::pwhash_msec() const {
   BOTAN_STATE_CHECK(m_pwhash_duration.has_value());
   return m_pwhash_duration.value();
}

std::string KeyEncryptionOptions::default_cipher() {
   return "AES-256/CBC";
}

std::string KeyEncryptionOptions::default_pwhash() {
   // TODO(Botan4) Consider changing this to Scrypt
   return "SHA-512";
}

std::chrono::milliseconds KeyEncryptionOptions::default_pwhash_duration() {
   return std::chrono::milliseconds(300);
}

KeyEncryptionOptions::KeyEncryptionOptions(std::string_view cipher,
                                           std::string_view pwhash,
                                           std::chrono::milliseconds pwhash_duration) :
      m_cipher(cipher.empty() ? default_cipher() : cipher),
      m_pwhash(pwhash.empty() ? default_pwhash() : pwhash),
      m_pwhash_duration(pwhash_duration) {
   BOTAN_ARG_CHECK(OID::from_name(m_cipher).has_value(), "Cipher must have an OID assigned");
   BOTAN_ARG_CHECK(OID::from_name(m_pwhash).has_value(), "Password hash must have an OID assigned");
   BOTAN_ARG_CHECK(m_pwhash_duration.value().count() > 0, "Invalid password hash duration");
}

KeyEncryptionOptions::KeyEncryptionOptions(std::string_view cipher, std::string_view pwhash, size_t pwhash_iterations) :
      m_cipher(cipher.empty() ? default_cipher() : cipher),
      m_pwhash(pwhash.empty() ? default_pwhash() : pwhash),
      m_pwhash_iterations(pwhash_iterations) {
   BOTAN_ARG_CHECK(OID::from_name(m_cipher).has_value(), "Cipher must have an OID assigned");
   BOTAN_ARG_CHECK(OID::from_name(m_pwhash).has_value(), "Password hash must have an OID assigned");
   BOTAN_ARG_CHECK(m_pwhash_iterations.value() >= 1, "Invalid password hash iteration count");
}

KeyEncryptionOptions KeyEncryptionOptions::_from_pbe_string(std::string_view pbe_algo, std::chrono::milliseconds msec) {
   SCAN_Name request(pbe_algo);

   if(request.arg_count() != 2 || (request.algo_name() != "PBE-PKCS5v20" && request.algo_name() != "PBES2")) {
      throw Invalid_Argument(fmt("Unsupported PBE '{}'", pbe_algo));
   }

   return KeyEncryptionOptions(request.arg(0), request.arg(1), msec);
}

EncryptedPrivateKey encrypt_private_key(const Private_Key& key,
                                        std::string_view password,
                                        RandomNumberGenerator& rng,
                                        const KeyEncryptionOptions& options) {
   auto raw_pkcs8 = key.private_key_info();

   size_t iterations_out = 0;

   const auto [alg_id, pkcs8] = [&]() -> std::pair<AlgorithmIdentifier, std::vector<uint8_t>> {
#if defined(BOTAN_HAS_PKCS5_PBES2)
      const auto& cipher = options.cipher();
      const auto& pwhash = options.pwhash();

      if(options.using_duration()) {
         return pbes2_encrypt_msec(raw_pkcs8, password, options.pwhash_msec(), &iterations_out, cipher, pwhash, rng);
      } else {
         return pbes2_encrypt_iter(raw_pkcs8, password, options.pwhash_iterations(), cipher, pwhash, rng);
      }
#else
      BOTAN_UNUSED(password, rng);
      throw Encoding_Error("Cannot encrypt PKCS8 because PBES2 was disabled in build");
#endif
   }();

   std::vector<uint8_t> output;
   DER_Encoder der(output);
   der.start_sequence().encode(alg_id).encode(pkcs8, ASN1_Type::OctetString).end_cons();

   // The iterations_out will not be set for Scrypt
   if(options.using_duration()) {
      return EncryptedPrivateKey(output, iterations_out);
   } else {
      return EncryptedPrivateKey(output, options.pwhash_iterations());
   }
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
