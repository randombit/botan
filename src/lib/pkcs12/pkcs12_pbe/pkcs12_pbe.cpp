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

#include <algorithm>

#include <botan/internal/pbes2.h>

namespace Botan {

namespace {

// Maps a PKCS#12 PBE OID/name to its cipher parameters
struct PKCS12_PBE_Params {
      OID oid;
      std::string cipher_name;
      size_t key_len;
};

PKCS12_PBE_Params pkcs12_pbe_params_for_oid(const OID& oid) {
   static const OID sha1_3des = OID::from_string("PBE-SHA1-3DES");
   if(oid == sha1_3des) {
      return {sha1_3des, "TripleDES/CBC", 24};
   }
   static const OID sha1_2des = OID::from_string("PBE-SHA1-2DES");
   if(oid == sha1_2des) {
      return {sha1_2des, "TripleDES/CBC", 16};
   }
   throw Decoding_Error(fmt("Unsupported PKCS#12 PBE algorithm: {}", oid.to_string()));
}

PKCS12_PBE_Params pkcs12_pbe_params_for_algo(std::string_view algo) {
   static const OID sha1_3des = OID::from_string("PBE-SHA1-3DES");
   static const OID sha1_2des = OID::from_string("PBE-SHA1-2DES");
   if(algo == "PBE-SHA1-3DES") {
      return {sha1_3des, "TripleDES/CBC", 24};
   }
   if(algo == "PBE-SHA1-2DES") {
      return {sha1_2des, "TripleDES/CBC", 16};
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

   const PKCS12_KDF kdf_key(HashFunction::create_or_throw("SHA-1"), 1, iterations);
   kdf_key.derive_key(key.data(), params.key_len, password.data(), password.size(), salt.data(), salt.size());

   const PKCS12_KDF kdf_iv(HashFunction::create_or_throw("SHA-1"), 2, iterations);
   kdf_iv.derive_key(iv.data(), iv_len, password.data(), password.size(), salt.data(), salt.size());

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

   static const OID pbes2_oid = OID::from_string("PBE-PKCS5v20");
   if(oid == pbes2_oid) {
      return pbes2_decrypt(ciphertext, password, pbe_algo.parameters());
   }

   std::vector<uint8_t> salt;
   size_t iterations = 0;
   BER_Decoder(pbe_algo.parameters())
      .start_sequence()
      .decode(salt, ASN1_Type::OctetString)
      .decode(iterations)
      .verify_end()
      .end_cons();

   if(iterations == 0 || iterations > PKCS12_MAX_ITERATIONS) {
      throw Decoding_Error(fmt("PKCS#12 PBE has invalid iteration count: {}", iterations));
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
   if(iterations == 0 || iterations > PKCS12_MAX_ITERATIONS) {
      throw Invalid_Argument(fmt("PKCS#12 PBE: iteration count must be between 1 and {}", PKCS12_MAX_ITERATIONS));
   }

   if(algo == "PBES2-SHA256-AES256") {
      auto [aid, ct] = pbes2_encrypt_iter(plaintext, password, iterations, "AES-256/CBC", "SHA-256", rng);
      return {std::move(aid), std::move(ct)};
   }
   if(algo == "PBES2-SHA256-AES128") {
      auto [aid, ct] = pbes2_encrypt_iter(plaintext, password, iterations, "AES-128/CBC", "SHA-256", rng);
      return {std::move(aid), std::move(ct)};
   }

   const auto params = pkcs12_pbe_params_for_algo(algo);

   std::vector<uint8_t> salt(8);
   rng.randomize(salt.data(), salt.size());

   auto [key, iv] = pkcs12_derive_key_iv(password, salt, iterations, params);

   auto cipher = Cipher_Mode::create_or_throw(params.cipher_name, Cipher_Dir::Encryption);
   cipher->set_key(key);
   cipher->start(iv);

   std::vector<uint8_t> ciphertext(plaintext.begin(), plaintext.end());
   cipher->finish(ciphertext);

   std::vector<uint8_t> enc_params;
   DER_Encoder(enc_params).start_sequence().encode(salt, ASN1_Type::OctetString).encode(iterations).end_cons();

   return {AlgorithmIdentifier(params.oid, enc_params), std::move(ciphertext)};
}

}  // namespace Botan
