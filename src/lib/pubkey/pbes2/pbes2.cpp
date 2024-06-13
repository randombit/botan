/*
* PKCS #5 PBES2
* (C) 1999-2008,2014,2021 Jack Lloyd
* (C) 2018 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pbes2.h>

#include <botan/asn1_obj.h>
#include <botan/ber_dec.h>
#include <botan/cipher_mode.h>
#include <botan/der_enc.h>
#include <botan/pwdhash.h>
#include <botan/rng.h>
#include <botan/internal/fmt.h>
#include <botan/internal/parsing.h>

namespace Botan {

namespace {

bool known_pbes_cipher_mode(std::string_view mode) {
   return (mode == "CBC" || mode == "GCM" || mode == "SIV");
}

secure_vector<uint8_t> derive_key(std::string_view passphrase,
                                  const AlgorithmIdentifier& kdf_algo,
                                  size_t default_key_size) {
   if(kdf_algo.oid() == OID::from_string("PKCS5.PBKDF2")) {
      secure_vector<uint8_t> salt;
      size_t iterations = 0, key_length = 0;

      AlgorithmIdentifier prf_algo;
      BER_Decoder(kdf_algo.parameters())
         .start_sequence()
         .decode(salt, ASN1_Type::OctetString)
         .decode(iterations)
         .decode_optional(key_length, ASN1_Type::Integer, ASN1_Class::Universal)
         .decode_optional(prf_algo,
                          ASN1_Type::Sequence,
                          ASN1_Class::Constructed,
                          AlgorithmIdentifier("HMAC(SHA-1)", AlgorithmIdentifier::USE_NULL_PARAM))
         .end_cons();

      if(salt.size() < 8) {
         throw Decoding_Error("PBE-PKCS5 v2.0: Encoded salt is too small");
      }

      if(key_length == 0) {
         key_length = default_key_size;
      }

      const std::string prf = prf_algo.oid().human_name_or_empty();
      if(prf.empty() || !prf.starts_with("HMAC")) {
         throw Decoding_Error(fmt("Unknown PBES2 PRF {}", prf_algo.oid()));
      }

      auto pbkdf_fam = PasswordHashFamily::create_or_throw(fmt("PBKDF2({})", prf));
      auto pbkdf = pbkdf_fam->from_params(iterations);

      secure_vector<uint8_t> derived_key(key_length);
      pbkdf->hash(derived_key, passphrase, salt);
      return derived_key;
   } else if(kdf_algo.oid() == OID::from_string("Scrypt")) {
      secure_vector<uint8_t> salt;
      size_t N = 0, r = 0, p = 0;
      size_t key_length = 0;

      AlgorithmIdentifier prf_algo;
      BER_Decoder(kdf_algo.parameters())
         .start_sequence()
         .decode(salt, ASN1_Type::OctetString)
         .decode(N)
         .decode(r)
         .decode(p)
         .decode_optional(key_length, ASN1_Type::Integer, ASN1_Class::Universal)
         .end_cons();

      if(key_length == 0) {
         key_length = default_key_size;
      }

      secure_vector<uint8_t> derived_key(key_length);

      auto pwdhash_fam = PasswordHashFamily::create_or_throw("Scrypt");
      auto pwdhash = pwdhash_fam->from_params(N, r, p);
      pwdhash->hash(derived_key, passphrase, salt);

      return derived_key;
   } else {
      throw Decoding_Error(fmt("PBE-PKCS5 v2.0: Unknown KDF algorithm {}", kdf_algo.oid()));
   }
}

secure_vector<uint8_t> derive_key(std::string_view passphrase,
                                  std::string_view digest,
                                  RandomNumberGenerator& rng,
                                  size_t* msec_in_iterations_out,
                                  size_t iterations_if_msec_null,
                                  size_t key_length,
                                  bool include_key_length_in_struct,
                                  AlgorithmIdentifier& kdf_algo) {
   const size_t salt_len = 16;
   const secure_vector<uint8_t> salt = rng.random_vec(salt_len);

   if(digest == "Scrypt") {
      auto pwhash_fam = PasswordHashFamily::create_or_throw("Scrypt");

      std::unique_ptr<PasswordHash> pwhash;

      if(msec_in_iterations_out) {
         const std::chrono::milliseconds msec(*msec_in_iterations_out);
         pwhash = pwhash_fam->tune(key_length, msec);
      } else {
         pwhash = pwhash_fam->from_iterations(iterations_if_msec_null);
      }

      secure_vector<uint8_t> key(key_length);
      pwhash->hash(key, passphrase, salt);

      const size_t N = pwhash->memory_param();
      const size_t r = pwhash->iterations();
      const size_t p = pwhash->parallelism();

      if(msec_in_iterations_out) {
         *msec_in_iterations_out = 0;
      }

      std::vector<uint8_t> scrypt_params;
      DER_Encoder(scrypt_params)
         .start_sequence()
         .encode(salt, ASN1_Type::OctetString)
         .encode(N)
         .encode(r)
         .encode(p)
         .encode_if(include_key_length_in_struct, key_length)
         .end_cons();

      kdf_algo = AlgorithmIdentifier(OID::from_string("Scrypt"), scrypt_params);
      return key;
   } else {
      const std::string prf = fmt("HMAC({})", digest);
      const std::string pbkdf_name = fmt("PBKDF2({})", prf);

      auto pwhash_fam = PasswordHashFamily::create(pbkdf_name);
      if(!pwhash_fam) {
         throw Invalid_Argument(fmt("Unknown password hash digest {}", digest));
      }

      std::unique_ptr<PasswordHash> pwhash;

      if(msec_in_iterations_out) {
         const std::chrono::milliseconds msec(*msec_in_iterations_out);
         pwhash = pwhash_fam->tune(key_length, msec);
      } else {
         pwhash = pwhash_fam->from_iterations(iterations_if_msec_null);
      }

      secure_vector<uint8_t> key(key_length);
      pwhash->hash(key, passphrase, salt);

      std::vector<uint8_t> pbkdf2_params;

      const size_t iterations = pwhash->iterations();

      if(msec_in_iterations_out) {
         *msec_in_iterations_out = iterations;
      }

      DER_Encoder(pbkdf2_params)
         .start_sequence()
         .encode(salt, ASN1_Type::OctetString)
         .encode(iterations)
         .encode_if(include_key_length_in_struct, key_length)
         .encode_if(prf != "HMAC(SHA-1)", AlgorithmIdentifier(prf, AlgorithmIdentifier::USE_NULL_PARAM))
         .end_cons();

      kdf_algo = AlgorithmIdentifier("PKCS5.PBKDF2", pbkdf2_params);
      return key;
   }
}

/*
* PKCS#5 v2.0 PBE Encryption
*/
std::pair<AlgorithmIdentifier, std::vector<uint8_t>> pbes2_encrypt_shared(std::span<const uint8_t> key_bits,
                                                                          std::string_view passphrase,
                                                                          size_t* msec_in_iterations_out,
                                                                          size_t iterations_if_msec_null,
                                                                          std::string_view cipher,
                                                                          std::string_view prf,
                                                                          RandomNumberGenerator& rng) {
   auto enc = Cipher_Mode::create(cipher, Cipher_Dir::Encryption);

   const auto cipher_spec = split_on(cipher, '/');

   if(cipher_spec.size() != 2 || !known_pbes_cipher_mode(cipher_spec[1]) || !enc) {
      throw Encoding_Error(fmt("PBE-PKCS5 v2.0: Invalid or unavailable cipher '{}'", cipher));
   }

   const size_t key_length = enc->key_spec().maximum_keylength();

   const secure_vector<uint8_t> iv = rng.random_vec(enc->default_nonce_length());

   AlgorithmIdentifier kdf_algo;

   const bool include_key_length_in_struct = enc->key_spec().minimum_keylength() != enc->key_spec().maximum_keylength();

   const auto derived_key = derive_key(passphrase,
                                       prf,
                                       rng,
                                       msec_in_iterations_out,
                                       iterations_if_msec_null,
                                       key_length,
                                       include_key_length_in_struct,
                                       kdf_algo);

   enc->set_key(derived_key);
   enc->start(iv);
   secure_vector<uint8_t> ctext(key_bits.begin(), key_bits.end());
   enc->finish(ctext);

   std::vector<uint8_t> encoded_iv;
   DER_Encoder(encoded_iv).encode(iv, ASN1_Type::OctetString);

   std::vector<uint8_t> pbes2_params;
   DER_Encoder(pbes2_params)
      .start_sequence()
      .encode(kdf_algo)
      .encode(AlgorithmIdentifier(cipher, encoded_iv))
      .end_cons();

   AlgorithmIdentifier id(OID::from_string("PBE-PKCS5v20"), pbes2_params);

   return std::make_pair(id, unlock(ctext));
}

}  // namespace

std::pair<AlgorithmIdentifier, std::vector<uint8_t>> pbes2_encrypt(std::span<const uint8_t> key_bits,
                                                                   std::string_view passphrase,
                                                                   std::chrono::milliseconds msec,
                                                                   std::string_view cipher,
                                                                   std::string_view digest,
                                                                   RandomNumberGenerator& rng) {
   size_t msec_in_iterations_out = static_cast<size_t>(msec.count());
   return pbes2_encrypt_shared(key_bits, passphrase, &msec_in_iterations_out, 0, cipher, digest, rng);
   // return value msec_in_iterations_out discarded
}

std::pair<AlgorithmIdentifier, std::vector<uint8_t>> pbes2_encrypt_msec(std::span<const uint8_t> key_bits,
                                                                        std::string_view passphrase,
                                                                        std::chrono::milliseconds msec,
                                                                        size_t* out_iterations_if_nonnull,
                                                                        std::string_view cipher,
                                                                        std::string_view digest,
                                                                        RandomNumberGenerator& rng) {
   size_t msec_in_iterations_out = static_cast<size_t>(msec.count());

   auto ret = pbes2_encrypt_shared(key_bits, passphrase, &msec_in_iterations_out, 0, cipher, digest, rng);

   if(out_iterations_if_nonnull) {
      *out_iterations_if_nonnull = msec_in_iterations_out;
   }

   return ret;
}

std::pair<AlgorithmIdentifier, std::vector<uint8_t>> pbes2_encrypt_iter(std::span<const uint8_t> key_bits,
                                                                        std::string_view passphrase,
                                                                        size_t pbkdf_iter,
                                                                        std::string_view cipher,
                                                                        std::string_view digest,
                                                                        RandomNumberGenerator& rng) {
   return pbes2_encrypt_shared(key_bits, passphrase, nullptr, pbkdf_iter, cipher, digest, rng);
}

secure_vector<uint8_t> pbes2_decrypt(std::span<const uint8_t> key_bits,
                                     std::string_view passphrase,
                                     const std::vector<uint8_t>& params) {
   AlgorithmIdentifier kdf_algo, enc_algo;

   BER_Decoder(params).start_sequence().decode(kdf_algo).decode(enc_algo).end_cons();

   const std::string cipher = enc_algo.oid().human_name_or_empty();
   const auto cipher_spec = split_on(cipher, '/');
   if(cipher_spec.size() != 2 || !known_pbes_cipher_mode(cipher_spec[1])) {
      throw Decoding_Error(fmt("PBE-PKCS5 v2.0: Unknown/invalid cipher OID {}", enc_algo.oid()));
   }

   secure_vector<uint8_t> iv;
   BER_Decoder(enc_algo.parameters()).decode(iv, ASN1_Type::OctetString).verify_end();

   auto dec = Cipher_Mode::create(cipher, Cipher_Dir::Decryption);
   if(!dec) {
      throw Decoding_Error(fmt("PBE-PKCS5 cannot decrypt no cipher '{}'", cipher));
   }

   dec->set_key(derive_key(passphrase, kdf_algo, dec->key_spec().maximum_keylength()));

   dec->start(iv);

   secure_vector<uint8_t> buf(key_bits.begin(), key_bits.end());
   dec->finish(buf);

   return buf;
}

}  // namespace Botan
