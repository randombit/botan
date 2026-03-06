/*
* PKCS#12 PBE (RFC 7292 Appendix B)
* (C) 2026 Damiano Mazzella
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pkcs12_pbe.h>

#include <botan/asn1_obj.h>
#include <botan/ber_dec.h>
#include <botan/cipher_mode.h>
#include <botan/der_enc.h>
#include <botan/exceptn.h>
#include <botan/rng.h>
#include <botan/internal/fmt.h>
#include <botan/internal/pkcs12_kdf.h>

#if defined(BOTAN_HAS_PKCS5_PBES2)
   #include <botan/internal/pbes2.h>
#endif

namespace Botan {

namespace {

// Maps a PKCS#12 PBE OID/name to its cipher parameters
struct PKCS12_PBE_Params {
      OID oid;
      std::string cipher_name;
      size_t key_len;
};

PKCS12_PBE_Params pkcs12_pbe_params_for_oid(const OID& oid) {
   if(oid == OID::from_string("PBE-SHA1-3DES")) {
      return {OID::from_string("PBE-SHA1-3DES"), "TripleDES/CBC", 24};
   }
   if(oid == OID::from_string("PBE-SHA1-2DES")) {
      return {OID::from_string("PBE-SHA1-2DES"), "TripleDES/CBC", 16};
   }
   throw Decoding_Error(fmt("Unsupported PKCS#12 PBE algorithm: {}", oid.to_string()));
}

PKCS12_PBE_Params pkcs12_pbe_params_for_algo(std::string_view algo) {
   if(algo == "PBE-SHA1-3DES" || algo.empty()) {
      return {OID::from_string("PBE-SHA1-3DES"), "TripleDES/CBC", 24};
   }
   if(algo == "PBE-SHA1-2DES") {
      return {OID::from_string("PBE-SHA1-2DES"), "TripleDES/CBC", 16};
   }
   throw Invalid_Argument(fmt("Unsupported PKCS#12 PBE algorithm: {}", algo));
}

// Derive key and IV via PKCS#12 KDF; expands 2-key 3DES (key_len==16) to 24 bytes
std::pair<secure_vector<uint8_t>, secure_vector<uint8_t>> pkcs12_derive_key_iv(std::string_view password,
                                                                               const std::vector<uint8_t>& salt,
                                                                               size_t iterations,
                                                                               const PKCS12_PBE_Params& params) {
   constexpr size_t iv_len = 8;  // DES/3DES block size
   secure_vector<uint8_t> key(params.key_len);
   secure_vector<uint8_t> iv(iv_len);
   pkcs12_kdf(key.data(), params.key_len, password, salt.data(), salt.size(), iterations, 1);
   pkcs12_kdf(iv.data(), iv_len, password, salt.data(), salt.size(), iterations, 2);
   if(params.key_len == 16) {  // 2DES: expand to 24 bytes by repeating the first key
      key.resize(24);
      std::copy(key.begin(), key.begin() + 8, key.begin() + 16);
   }
   return {std::move(key), std::move(iv)};
}

}  // namespace

secure_vector<uint8_t> pkcs12_pbe_decrypt(std::span<const uint8_t> ciphertext,
                                          std::string_view password,
                                          const AlgorithmIdentifier& pbe_algo) {
   const OID& oid = pbe_algo.oid();

   if(oid == OID::from_string("PBE-PKCS5v20")) {
#if defined(BOTAN_HAS_PKCS5_PBES2)
      return pbes2_decrypt(ciphertext, password, pbe_algo.parameters());
#else
      throw Decoding_Error("PBES2 encryption used but PBES2 support not available");
#endif
   }

   std::vector<uint8_t> salt;
   size_t iterations = 0;
   BER_Decoder(pbe_algo.parameters())
      .start_sequence()
      .decode(salt, ASN1_Type::OctetString)
      .decode(iterations)
      .end_cons();

   if(iterations == 0 || iterations > 1000000) {
      throw Decoding_Error("PKCS#12 PBE has invalid iteration count");
   }

   const auto params = pkcs12_pbe_params_for_oid(oid);
   auto [key, iv] = pkcs12_derive_key_iv(password, salt, iterations, params);

   auto cipher = Cipher_Mode::create_or_throw(params.cipher_name, Cipher_Dir::Decryption);
   cipher->set_key(key);
   cipher->start(iv);

   secure_vector<uint8_t> plaintext(ciphertext.begin(), ciphertext.end());
   cipher->finish(plaintext);

   return plaintext;
}

std::pair<AlgorithmIdentifier, std::vector<uint8_t>> pkcs12_pbe_encrypt(std::span<const uint8_t> plaintext,
                                                                        std::string_view password,
                                                                        std::string_view algo,
                                                                        size_t iterations,
                                                                        RandomNumberGenerator& rng) {
   if(algo == "PBES2-SHA256-AES256" || algo == "PBES2(AES-256/CBC,SHA-256)") {
#if defined(BOTAN_HAS_PKCS5_PBES2)
      return pbes2_encrypt_iter(plaintext, password, iterations, "AES-256/CBC", "SHA-256", rng);
#else
      throw Invalid_Argument("PBES2 requested but PBES2 support not available");
#endif
   }
   if(algo == "PBES2-SHA256-AES128" || algo == "PBES2(AES-128/CBC,SHA-256)") {
#if defined(BOTAN_HAS_PKCS5_PBES2)
      return pbes2_encrypt_iter(plaintext, password, iterations, "AES-128/CBC", "SHA-256", rng);
#else
      throw Invalid_Argument("PBES2 requested but PBES2 support not available");
#endif
   }

   const auto params = pkcs12_pbe_params_for_algo(algo);

   std::vector<uint8_t> salt(8);
   rng.randomize(salt.data(), salt.size());

   auto [key, iv] = pkcs12_derive_key_iv(password, salt, iterations, params);

   auto cipher = Cipher_Mode::create_or_throw(params.cipher_name, Cipher_Dir::Encryption);
   cipher->set_key(key);
   cipher->start(iv);

   secure_vector<uint8_t> ciphertext(plaintext.begin(), plaintext.end());
   cipher->finish(ciphertext);

   std::vector<uint8_t> enc_params;
   DER_Encoder(enc_params).start_sequence().encode(salt, ASN1_Type::OctetString).encode(iterations).end_cons();

   return {AlgorithmIdentifier(params.oid, enc_params), std::vector<uint8_t>(ciphertext.begin(), ciphertext.end())};
}

}  // namespace Botan
