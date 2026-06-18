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
#include <botan/internal/bit_ops.h>
#include <botan/internal/fmt.h>
#include <botan/internal/parsing.h>

namespace Botan {

namespace {

class Pbes2KdfParameters {
   public:
      virtual ~Pbes2KdfParameters() = default;
      Pbes2KdfParameters(const Pbes2KdfParameters& other) = delete;
      Pbes2KdfParameters(Pbes2KdfParameters&& other) = delete;
      Pbes2KdfParameters& operator=(const Pbes2KdfParameters& other) = delete;
      Pbes2KdfParameters& operator=(Pbes2KdfParameters&& other) = delete;

      static std::unique_ptr<Pbes2KdfParameters> decode(const AlgorithmIdentifier& alg_id);

      static std::unique_ptr<Pbes2KdfParameters> tune(std::string_view digest,
                                                      RandomNumberGenerator& rng,
                                                      size_t key_length,
                                                      size_t* msec_in_iterations_out,
                                                      size_t iterations_if_msec_null);

      secure_vector<uint8_t> derive_key(std::string_view passphrase, size_t default_key_size) const;

      virtual AlgorithmIdentifier algorithm_identifier(bool include_key_length) const = 0;

   protected:
      static constexpr size_t DefaultSaltBytes = 16;

      const PasswordHash& pwdhash() const { return *m_pwdhash; }

      std::optional<size_t> key_length() const { return m_key_length; }

      std::span<const uint8_t> salt() const { return m_salt; }

      Pbes2KdfParameters(std::vector<uint8_t> salt,
                         std::optional<size_t> key_length,
                         std::unique_ptr<PasswordHash> pwdhash) :
            m_salt(std::move(salt)), m_key_length(key_length), m_pwdhash(std::move(pwdhash)) {}

      static std::vector<uint8_t> generate_salt(RandomNumberGenerator& rng) {
         return rng.random_vec<std::vector<uint8_t>>(DefaultSaltBytes);
      }

      static void validate_pbes2_params(size_t salt_len, std::optional<size_t> key_length) {
         if(key_length && (key_length.value() < 8 || key_length.value() >= 256)) {
            throw Decoding_Error(fmt("PBES2: Encoded key length ({}) is invalid", key_length.value()));
         }
         if(salt_len < 8) {
            throw Decoding_Error("PBES2: Encoded salt is too small");
         }
      }

   private:
      std::vector<uint8_t> m_salt;
      std::optional<size_t> m_key_length;
      std::unique_ptr<PasswordHash> m_pwdhash;
};

class Pbes2Pbkdf2Parameters final : public Pbes2KdfParameters {
   public:
      static std::unique_ptr<Pbes2Pbkdf2Parameters> decode(const AlgorithmIdentifier& kdf_algo);

      static std::unique_ptr<Pbes2Pbkdf2Parameters> tune(std::string_view digest,
                                                         RandomNumberGenerator& rng,
                                                         size_t key_length,
                                                         size_t* msec_in_iterations_out,
                                                         size_t iterations_if_msec_null);

      Pbes2Pbkdf2Parameters(std::vector<uint8_t> salt,
                            std::optional<size_t> key_length,
                            std::unique_ptr<PasswordHash> pwdhash,
                            std::string prf) :
            Pbes2KdfParameters(std::move(salt), key_length, std::move(pwdhash)), m_prf(std::move(prf)) {}

      AlgorithmIdentifier algorithm_identifier(bool include_key_length) const override;

   private:
      static void validate_params(size_t iterations);

      std::string m_prf;
};

class Pbes2ScryptParameters final : public Pbes2KdfParameters {
   public:
      static std::unique_ptr<Pbes2ScryptParameters> decode(const AlgorithmIdentifier& kdf_algo);

      static std::unique_ptr<Pbes2ScryptParameters> tune(RandomNumberGenerator& rng,
                                                         size_t key_length,
                                                         size_t* msec_in_iterations_out,
                                                         size_t iterations_if_msec_null);

      Pbes2ScryptParameters(std::vector<uint8_t> salt,
                            std::optional<size_t> key_length,
                            std::unique_ptr<PasswordHash> pwdhash) :
            Pbes2KdfParameters(std::move(salt), key_length, std::move(pwdhash)) {}

      AlgorithmIdentifier algorithm_identifier(bool include_key_length) const override;

   private:
      static void validate_params(size_t N, size_t r, size_t p);
};

/* Dispatching */

secure_vector<uint8_t> Pbes2KdfParameters::derive_key(std::string_view passphrase, size_t default_key_size) const {
   const size_t kl = m_key_length.value_or(default_key_size);
   secure_vector<uint8_t> key(kl);
   m_pwdhash->hash(key, passphrase, m_salt);
   return key;
}

std::unique_ptr<Pbes2KdfParameters> Pbes2KdfParameters::tune(std::string_view digest,
                                                             RandomNumberGenerator& rng,
                                                             size_t key_length,
                                                             size_t* msec_in_iterations_out,
                                                             size_t iterations_if_msec_null) {
   if(digest == "Scrypt") {
      return Pbes2ScryptParameters::tune(rng, key_length, msec_in_iterations_out, iterations_if_msec_null);
   } else {
      return Pbes2Pbkdf2Parameters::tune(digest, rng, key_length, msec_in_iterations_out, iterations_if_msec_null);
   }
}

std::unique_ptr<Pbes2KdfParameters> Pbes2KdfParameters::decode(const AlgorithmIdentifier& kdf_algo) {
   if(kdf_algo.oid() == OID::from_string("PKCS5.PBKDF2")) {
      return Pbes2Pbkdf2Parameters::decode(kdf_algo);
   } else if(kdf_algo.oid() == OID::from_string("Scrypt")) {
      return Pbes2ScryptParameters::decode(kdf_algo);
   } else {
      throw Decoding_Error(fmt("PBES2 unknown or unhandled KDF algorithm '{}'", kdf_algo.oid()));
   }
}

/* PBES2 PBKDF2 handling */

std::unique_ptr<Pbes2Pbkdf2Parameters> Pbes2Pbkdf2Parameters::tune(std::string_view digest,
                                                                   RandomNumberGenerator& rng,
                                                                   size_t key_length,
                                                                   size_t* msec_in_iterations_out,
                                                                   size_t iterations_if_msec_null) {
   const std::string prf = fmt("HMAC({})", digest);

   auto pwhash_fam = PasswordHashFamily::create(fmt("PBKDF2({})", prf));
   if(!pwhash_fam) {
      throw Invalid_Argument(fmt("Unknown password hash digest {}", digest));
   }

   std::unique_ptr<PasswordHash> pwhash;
   if(msec_in_iterations_out != nullptr) {
      pwhash = pwhash_fam->tune_params(key_length, *msec_in_iterations_out);
      *msec_in_iterations_out = pwhash->iterations();
   } else {
      pwhash = pwhash_fam->from_iterations(iterations_if_msec_null);
   }

   // Ensure we will accept these same parameters when decoding
   validate_params(pwhash->iterations());

   return std::make_unique<Pbes2Pbkdf2Parameters>(generate_salt(rng), key_length, std::move(pwhash), prf);
}

//static
void Pbes2Pbkdf2Parameters::validate_params(size_t iterations) {
   // The upper bound corresponds to about 10 to 60 seconds of CPU time
   // (depending on hash and hardware) which seems sufficient...
   if(iterations == 0 || iterations > (1U << 26)) {
      throw Decoding_Error(fmt("PBES2: Invalid or unacceptable PBKDF2 iteration count ({})", iterations));
   }
}

std::unique_ptr<Pbes2Pbkdf2Parameters> Pbes2Pbkdf2Parameters::decode(const AlgorithmIdentifier& kdf_algo) {
   std::vector<uint8_t> salt;
   size_t iterations = 0;
   std::optional<size_t> key_length;

   AlgorithmIdentifier prf_algo;
   BER_Decoder(kdf_algo.parameters(), BER_Decoder::Limits::DER())
      .start_sequence()
      .decode(salt, ASN1_Type::OctetString)
      .decode(iterations)
      .decode_optional(key_length, ASN1_Type::Integer, ASN1_Class::Universal)
      .decode_optional(prf_algo,
                       ASN1_Type::Sequence,
                       ASN1_Class::Constructed,
                       AlgorithmIdentifier("HMAC(SHA-1)", AlgorithmIdentifier::USE_NULL_PARAM))
      .end_cons()
      .verify_end();

   validate_pbes2_params(salt.size(), key_length);
   validate_params(iterations);

   const std::string prf = [&]() {
      if(const auto name = prf_algo.oid().registered_name()) {
         if(name->starts_with("HMAC")) {
            return *name;
         }
      }

      throw Decoding_Error(fmt("Unknown PBES2 PRF '{}'", prf_algo.oid()));
   }();

   // RFC 8018 A.2 defines the PBKDF2 PRFs with NULL parameters; accept NULL or
   // absent and reject any other parameter encoding rather than ignoring it.
   if(!prf_algo.parameters_are_null_or_empty()) {
      throw Decoding_Error("PBES2 PRF AlgorithmIdentifier has unexpected parameters");
   }

   auto pbkdf_fam = PasswordHashFamily::create_or_throw(fmt("PBKDF2({})", prf));
   auto pwdhash = pbkdf_fam->from_params(iterations);

   return std::make_unique<Pbes2Pbkdf2Parameters>(std::move(salt), key_length, std::move(pwdhash), prf);
}

AlgorithmIdentifier Pbes2Pbkdf2Parameters::algorithm_identifier(bool include_key_length) const {
   std::vector<uint8_t> params;
   DER_Encoder(params)
      .start_sequence()
      .encode(salt(), ASN1_Type::OctetString)
      .encode(pwdhash().iterations())
      .encode_if(include_key_length && key_length().has_value(), key_length().value_or(0))
      .encode_if(m_prf != "HMAC(SHA-1)", AlgorithmIdentifier(m_prf, AlgorithmIdentifier::USE_NULL_PARAM))
      .end_cons();
   return AlgorithmIdentifier("PKCS5.PBKDF2", params);
}

/* PBES2 Scrypt handling */

std::unique_ptr<Pbes2ScryptParameters> Pbes2ScryptParameters::tune(RandomNumberGenerator& rng,
                                                                   size_t key_length,
                                                                   size_t* msec_in_iterations_out,
                                                                   size_t iterations_if_msec_null) {
   auto pwhash_fam = PasswordHashFamily::create_or_throw("Scrypt");

   std::unique_ptr<PasswordHash> pwhash;
   if(msec_in_iterations_out != nullptr) {
      pwhash = pwhash_fam->tune_params(key_length, *msec_in_iterations_out);
      *msec_in_iterations_out = 0;
   } else {
      pwhash = pwhash_fam->from_iterations(iterations_if_msec_null);
   }

   // Ensure we will accept these same parameters when decoding
   validate_params(pwhash->memory_param(), pwhash->iterations(), pwhash->parallelism());

   return std::make_unique<Pbes2ScryptParameters>(generate_salt(rng), key_length, std::move(pwhash));
}

//static
void Pbes2ScryptParameters::validate_params(size_t N, size_t r, size_t p) {
   if(N <= 1 || N > 4194304 || !is_power_of_2(N)) {
      throw Decoding_Error(fmt("PBES2: Invalid or unacceptable Scrypt parameter N ({})", N));
   }
   if(r == 0 || r > 64) {
      throw Decoding_Error(fmt("PBES2: Invalid or unacceptable Scrypt parameter r ({})", r));
   }
   if(p == 0 || p >= 1024) {
      throw Decoding_Error(fmt("PBES2: Invalid or unacceptable Scrypt parameter p ({})", p));
   }
}

std::unique_ptr<Pbes2ScryptParameters> Pbes2ScryptParameters::decode(const AlgorithmIdentifier& kdf_algo) {
   std::vector<uint8_t> salt;
   size_t N = 0;
   size_t r = 0;
   size_t p = 0;
   std::optional<size_t> key_length;

   BER_Decoder(kdf_algo.parameters(), BER_Decoder::Limits::DER())
      .start_sequence()
      .decode(salt, ASN1_Type::OctetString)
      .decode(N)
      .decode(r)
      .decode(p)
      .decode_optional(key_length, ASN1_Type::Integer, ASN1_Class::Universal)
      .end_cons()
      .verify_end();

   validate_pbes2_params(salt.size(), key_length);
   validate_params(N, r, p);

   auto pwdhash_fam = PasswordHashFamily::create_or_throw("Scrypt");
   auto pwdhash = pwdhash_fam->from_params(N, r, p);

   return std::make_unique<Pbes2ScryptParameters>(std::move(salt), key_length, std::move(pwdhash));
}

AlgorithmIdentifier Pbes2ScryptParameters::algorithm_identifier(bool include_key_length) const {
   std::vector<uint8_t> params;
   DER_Encoder(params)
      .start_sequence()
      .encode(salt(), ASN1_Type::OctetString)
      .encode(pwdhash().memory_param())
      .encode(pwdhash().iterations())
      .encode(pwdhash().parallelism())
      .encode_if(include_key_length && key_length().has_value(), key_length().value_or(0))
      .end_cons();
   return AlgorithmIdentifier(OID::from_string("Scrypt"), params);
}

bool known_pbes_cipher_mode(std::string_view mode) {
   return (mode == "CBC" || mode == "GCM" || mode == "SIV");
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
      throw Encoding_Error(fmt("PBES2: Invalid or unavailable cipher '{}'", cipher));
   }

   const size_t key_length = enc->key_spec().maximum_keylength();

   const auto iv = rng.random_vec<std::vector<uint8_t>>(enc->default_nonce_length());

   const bool include_key_length_in_struct = enc->key_spec().minimum_keylength() != enc->key_spec().maximum_keylength();

   auto kdf_params = Pbes2KdfParameters::tune(prf, rng, key_length, msec_in_iterations_out, iterations_if_msec_null);
   const auto derived_key = kdf_params->derive_key(passphrase, key_length);
   const auto kdf_algo = kdf_params->algorithm_identifier(include_key_length_in_struct);

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

   const AlgorithmIdentifier id(OID::from_string("PBE-PKCS5v20"), pbes2_params);

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

   if(out_iterations_if_nonnull != nullptr) {
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
   AlgorithmIdentifier kdf_algo;
   AlgorithmIdentifier enc_algo;

   BER_Decoder(params, BER_Decoder::Limits::DER())
      .start_sequence()
      .decode(kdf_algo)
      .decode(enc_algo)
      .end_cons()
      .verify_end();

   const std::string cipher = [&]() -> std::string {
      if(const auto name = enc_algo.oid().registered_name()) {
         const auto cipher_spec = split_on(*name, '/');
         if(cipher_spec.size() == 2 && known_pbes_cipher_mode(cipher_spec[1])) {
            return *name;
         }
      }

      throw Decoding_Error(fmt("PBES2: Unknown/invalid cipher OID {}", enc_algo.oid()));
   }();

   std::vector<uint8_t> iv;
   BER_Decoder(enc_algo.parameters(), BER_Decoder::Limits::DER()).decode(iv, ASN1_Type::OctetString).verify_end();

   auto dec = Cipher_Mode::create(cipher, Cipher_Dir::Decryption);
   if(!dec) {
      throw Decoding_Error(fmt("PBES2 cannot decrypt due to unavailable cipher '{}'", cipher));
   }

   // The cipher parameters carry the IV (RFC 8018 B.2). Require the length be the
   // expected value; any other length has undocumented semantics.
   if(iv.size() != dec->default_nonce_length()) {
      throw Decoding_Error("PBES2 cipher AlgorithmIdentifier has invalid IV length");
   }

   const size_t default_key_size = dec->key_spec().maximum_keylength();
   auto pbkdf = Pbes2KdfParameters::decode(kdf_algo);
   dec->set_key(pbkdf->derive_key(passphrase, default_key_size));

   dec->start(iv);

   secure_vector<uint8_t> buf(key_bits.begin(), key_bits.end());
   dec->finish(buf);

   return buf;
}

}  // namespace Botan
