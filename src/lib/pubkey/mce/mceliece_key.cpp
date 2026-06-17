/*
 * (C) Copyright Projet SECRET, INRIA, Rocquencourt
 * (C) Bhaskar Biswas and  Nicolas Sendrier
 *
 * (C) 2014 cryptosource GmbH
 * (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
 * (C) 2015 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 *
 */

#include <botan/mceliece.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/rng.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/buffer_stuffer.h>
#include <botan/internal/code_based_util.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/mce_internal.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/polyn_gf2m.h>

namespace Botan {

McEliece_PrivateKey::McEliece_PrivateKey(const McEliece_PrivateKey&) = default;
McEliece_PrivateKey::McEliece_PrivateKey(McEliece_PrivateKey&&) noexcept = default;
McEliece_PrivateKey& McEliece_PrivateKey::operator=(const McEliece_PrivateKey&) = default;
McEliece_PrivateKey& McEliece_PrivateKey::operator=(McEliece_PrivateKey&&) noexcept = default;
McEliece_PrivateKey::~McEliece_PrivateKey() = default;

McEliece_PrivateKey::McEliece_PrivateKey(const polyn_gf2m& goppa_polyn,
                                         const std::vector<uint32_t>& parity_check_matrix_coeffs,
                                         const std::vector<polyn_gf2m>& square_root_matrix,
                                         const std::vector<gf2m>& inverse_support,
                                         const std::vector<uint8_t>& public_matrix) :
      McEliece_PublicKey(public_matrix, goppa_polyn.get_degree(), inverse_support.size()) {
   const size_t codimension = static_cast<size_t>(ceil_log2(inverse_support.size())) * goppa_polyn.get_degree();
   const size_t dimension = inverse_support.size() - codimension;
   m_private = std::make_shared<const McEliece_PrivateKeyInternal>(std::vector<polyn_gf2m>{goppa_polyn},
                                                                   square_root_matrix,
                                                                   inverse_support,
                                                                   parity_check_matrix_coeffs,
                                                                   codimension,
                                                                   dimension);
}

// NOLINTNEXTLINE(*-member-init)
McEliece_PrivateKey::McEliece_PrivateKey(RandomNumberGenerator& rng, size_t code_length, size_t t) {
   const uint32_t ext_deg = ceil_log2(code_length);
   *this = generate_mceliece_key(rng, ext_deg, code_length, t);
}

size_t McEliece_PublicKeyInternal::message_word_bit_length() const {
   const size_t codimension = ceil_log2(m_code_length) * m_t;
   return m_code_length - codimension;
}

secure_vector<uint8_t> McEliece_PublicKeyInternal::random_plaintext_element(RandomNumberGenerator& rng) const {
   const size_t bits = message_word_bit_length();

   secure_vector<uint8_t> plaintext((bits + 7) / 8);
   rng.randomize(plaintext.data(), plaintext.size());

   // unset unused bits in the last plaintext byte
   if(const uint32_t used = bits % 8) {
      const uint8_t mask = (1 << used) - 1;
      plaintext[plaintext.size() - 1] &= mask;
   }

   return plaintext;
}

McEliece_PublicKey::McEliece_PublicKey(const std::vector<uint8_t>& pub_matrix, size_t t, size_t the_code_length) :
      m_public(std::make_shared<const McEliece_PublicKeyInternal>(pub_matrix, t, the_code_length)) {}

size_t McEliece_PublicKey::get_t() const {
   return m_public->t();
}

size_t McEliece_PublicKey::get_code_length() const {
   return m_public->code_length();
}

const std::vector<uint8_t>& McEliece_PublicKey::get_public_matrix() const {
   return m_public->public_matrix();
}

size_t McEliece_PublicKey::get_message_word_bit_length() const {
   return m_public->message_word_bit_length();
}

secure_vector<uint8_t> McEliece_PublicKey::random_plaintext_element(RandomNumberGenerator& rng) const {
   return m_public->random_plaintext_element(rng);
}

const polyn_gf2m& McEliece_PrivateKey::get_goppa_polyn() const {
   return m_private->goppa_polyn();
}

const std::vector<uint32_t>& McEliece_PrivateKey::get_H_coeffs() const {
   return m_private->H_coeffs();
}

const std::vector<gf2m>& McEliece_PrivateKey::get_Linv() const {
   return m_private->Linv();
}

const std::vector<polyn_gf2m>& McEliece_PrivateKey::get_sqrtmod() const {
   return m_private->sqrtmod();
}

size_t McEliece_PrivateKey::get_dimension() const {
   return m_private->dimension();
}

size_t McEliece_PrivateKey::get_codimension() const {
   return m_private->codimension();
}

AlgorithmIdentifier McEliece_PublicKey::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

std::vector<uint8_t> McEliece_PublicKey::raw_public_key_bits() const {
   return m_public->public_matrix();
}

std::vector<uint8_t> McEliece_PublicKey::public_key_bits() const {
   std::vector<uint8_t> output;
   DER_Encoder(output)
      .start_sequence()
      .start_sequence()
      .encode(get_code_length())
      .encode(get_t())
      .end_cons()
      .encode(m_public->public_matrix(), ASN1_Type::OctetString)
      .end_cons();
   return output;
}

size_t McEliece_PublicKey::key_length() const {
   return m_public->code_length();
}

size_t McEliece_PublicKey::estimated_strength() const {
   return mceliece_work_factor(m_public->code_length(), m_public->t());
}

McEliece_PublicKey::McEliece_PublicKey(std::span<const uint8_t> key_bits) :
      McEliece_PublicKey(AlgorithmIdentifier(), key_bits) {}

McEliece_PublicKey::McEliece_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) {
   // The McEliece parameters are carried in the key bits; no AlgorithmIdentifier
   // parameters are defined.
   if(!alg_id.parameters_are_empty()) {
      throw Decoding_Error("Unexpected parameters for McEliece public key");
   }

   BER_Decoder dec(key_bits, BER_Decoder::Limits::DER());
   size_t n = 0;
   size_t t = 0;
   std::vector<uint8_t> public_matrix;
   dec.start_sequence()
      .start_sequence()
      .decode(n)
      .decode(t)
      .end_cons()
      .decode(public_matrix, ASN1_Type::OctetString)
      .end_cons()
      .verify_end();

   if(n == 0 || t == 0) {
      throw Decoding_Error("Invalid McEliece parameters");
   }

   // GF(2^m) field requires extension degree in [2, 16]
   const size_t ext_deg = ceil_log2(n);
   if(ext_deg < 2 || ext_deg > 16) {
      throw Decoding_Error("McEliece code length out of supported range");
   }

   // Since ext_deg >= 2, t >= n already implies ext_deg * t > n
   if(t >= n) {
      throw Decoding_Error("McEliece parameters are inconsistent");
   }

   const size_t codimension = ext_deg * t;

   // codimension must be strictly less than n, otherwise the code has no message bits
   if(codimension >= n) {
      throw Decoding_Error("McEliece parameters are inconsistent");
   }

   const size_t dimension = n - codimension;

   // public matrix is a dimension x codimension binary matrix stored as uint32_t rows
   const size_t expected_pubmat_size = dimension * bit_size_to_32bit_size(codimension) * sizeof(uint32_t);
   if(public_matrix.size() != expected_pubmat_size) {
      throw Decoding_Error("McEliece public matrix size does not match parameters");
   }

   m_public = std::make_shared<const McEliece_PublicKeyInternal>(std::move(public_matrix), t, n);
}

secure_vector<uint8_t> McEliece_PrivateKey::private_key_bits() const {
   DER_Encoder enc;
   enc.start_sequence()
      .start_sequence()
      .encode(get_code_length())
      .encode(get_t())
      .end_cons()
      .encode(m_public->public_matrix(), ASN1_Type::OctetString)
      .encode(m_private->goppa_polyn().encode(), ASN1_Type::OctetString);  // g as octet string
   enc.start_sequence();
   for(const auto& x : m_private->sqrtmod()) {
      enc.encode(x.encode(), ASN1_Type::OctetString);
   }
   enc.end_cons();
   secure_vector<uint8_t> enc_support;

   for(const uint16_t Linv : m_private->Linv()) {
      enc_support.push_back(get_byte<0>(Linv));
      enc_support.push_back(get_byte<1>(Linv));
   }
   enc.encode(enc_support, ASN1_Type::OctetString);
   secure_vector<uint8_t> enc_H;
   for(const uint32_t coef : m_private->H_coeffs()) {
      enc_H.push_back(get_byte<0>(coef));
      enc_H.push_back(get_byte<1>(coef));
      enc_H.push_back(get_byte<2>(coef));
      enc_H.push_back(get_byte<3>(coef));
   }
   enc.encode(enc_H, ASN1_Type::OctetString);
   enc.end_cons();
   return enc.get_contents();
}

bool McEliece_PrivateKey::check_key(RandomNumberGenerator& rng, bool /*unused*/) const {
   const secure_vector<uint8_t> plaintext = this->random_plaintext_element(rng);

   secure_vector<uint8_t> ciphertext;
   secure_vector<uint8_t> errors;
   mceliece_encrypt(ciphertext, errors, plaintext, *m_public, rng);

   secure_vector<uint8_t> plaintext_out;
   secure_vector<uint8_t> errors_out;
   mceliece_decrypt(plaintext_out, errors_out, ciphertext, *m_private);

   if(errors != errors_out || plaintext != plaintext_out) {
      return false;
   }

   return true;
}

McEliece_PrivateKey::McEliece_PrivateKey(std::span<const uint8_t> key_bits) :
      McEliece_PrivateKey(AlgorithmIdentifier(), key_bits) {}

McEliece_PrivateKey::McEliece_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) {
   // The McEliece parameters are carried in the key bits; no AlgorithmIdentifier
   // parameters are defined.
   if(!alg_id.parameters_are_empty()) {
      throw Decoding_Error("Unexpected parameters for McEliece private key");
   }

   size_t n = 0;
   size_t t = 0;
   std::vector<uint8_t> public_matrix;
   secure_vector<uint8_t> enc_g;
   BER_Decoder dec_base(key_bits, BER_Decoder::Limits::DER());
   BER_Decoder dec = dec_base.start_sequence();
   dec.start_sequence().decode(n).decode(t).end_cons();
   dec.decode(public_matrix, ASN1_Type::OctetString).decode(enc_g, ASN1_Type::OctetString);

   if(t == 0 || n == 0) {
      throw Decoding_Error("invalid McEliece parameters");
   }

   const uint32_t ext_deg = ceil_log2(n);

   if(ext_deg < 2 || ext_deg > 16) {
      throw Decoding_Error("McEliece code length out of supported range");
   }

   // Since ext_deg >= 2, t >= n already implies ext_deg * t > n
   if(t >= n) {
      throw Decoding_Error("McEliece parameters are inconsistent");
   }

   const size_t codimension = ext_deg * t;

   if(codimension >= n) {
      throw Decoding_Error("McEliece parameters are inconsistent");
   }

   const size_t dimension = n - codimension;
   const size_t expected_pubmat_size = dimension * bit_size_to_32bit_size(codimension) * sizeof(uint32_t);
   if(public_matrix.size() != expected_pubmat_size) {
      throw Decoding_Error("McEliece public matrix size does not match parameters");
   }

   auto sp_field = std::make_shared<GF2m_Field>(ext_deg);
   std::vector<polyn_gf2m> g = {polyn_gf2m(enc_g, sp_field)};
   if(g[0].get_degree() != static_cast<int>(t)) {
      throw Decoding_Error("degree of decoded Goppa polynomial is incorrect");
   }
   std::vector<polyn_gf2m> sqrtmod;
   BER_Decoder dec2 = dec.start_sequence();
   for(uint32_t i = 0; i < t / 2; i++) {
      secure_vector<uint8_t> sqrt_enc;
      dec2.decode(sqrt_enc, ASN1_Type::OctetString);
      while(sqrt_enc.size() < (t * 2)) {
         // ensure that the length is always t
         sqrt_enc.push_back(0);
         sqrt_enc.push_back(0);
      }
      if(sqrt_enc.size() != t * 2) {
         throw Decoding_Error("length of square root polynomial entry is too large");
      }
      sqrtmod.push_back(polyn_gf2m(sqrt_enc, sp_field));
   }
   secure_vector<uint8_t> enc_support;
   dec2.end_cons();
   dec.decode(enc_support, ASN1_Type::OctetString);
   if(enc_support.size() % 2 != 0) {
      throw Decoding_Error("encoded support has odd length");
   }
   if(enc_support.size() / 2 != n) {
      throw Decoding_Error("encoded support has length different from code length");
   }
   std::vector<gf2m> Linv;
   for(uint32_t i = 0; i < n * 2; i += 2) {
      const gf2m el = (enc_support[i] << 8) | enc_support[i + 1];
      Linv.push_back(el);
   }
   secure_vector<uint8_t> enc_H;
   dec.decode(enc_H, ASN1_Type::OctetString).end_cons().verify_end();
   if(enc_H.size() % 4 != 0) {
      throw Decoding_Error("encoded parity check matrix has length which is not a multiple of four");
   }
   if(enc_H.size() / 4 != bit_size_to_32bit_size(codimension) * n) {
      throw Decoding_Error("encoded parity check matrix has wrong length");
   }

   std::vector<uint32_t> coeffs;
   for(uint32_t i = 0; i < enc_H.size(); i += 4) {
      const uint32_t coeff = (enc_H[i] << 24) | (enc_H[i + 1] << 16) | (enc_H[i + 2] << 8) | enc_H[i + 3];
      coeffs.push_back(coeff);
   }

   m_public = std::make_shared<const McEliece_PublicKeyInternal>(std::move(public_matrix), t, n);
   m_private = std::make_shared<const McEliece_PrivateKeyInternal>(
      std::move(g), std::move(sqrtmod), std::move(Linv), std::move(coeffs), codimension, dimension);
}

bool McEliece_PrivateKey::operator==(const McEliece_PrivateKey& other) const {
   if(*static_cast<const McEliece_PublicKey*>(this) != *static_cast<const McEliece_PublicKey*>(&other)) {
      return false;
   }
   if(m_private->goppa_polyn_vec() != other.m_private->goppa_polyn_vec()) {
      return false;
   }

   if(m_private->sqrtmod() != other.m_private->sqrtmod()) {
      return false;
   }
   if(m_private->Linv() != other.m_private->Linv()) {
      return false;
   }
   if(m_private->H_coeffs() != other.m_private->H_coeffs()) {
      return false;
   }

   if(m_private->codimension() != other.m_private->codimension() ||
      m_private->dimension() != other.m_private->dimension()) {
      return false;
   }

   return true;
}

std::unique_ptr<Public_Key> McEliece_PrivateKey::public_key() const {
   return std::make_unique<McEliece_PublicKey>(get_public_matrix(), get_t(), get_code_length());
}

bool McEliece_PublicKey::operator==(const McEliece_PublicKey& other) const {
   if(m_public->public_matrix() != other.m_public->public_matrix()) {
      return false;
   }
   if(m_public->t() != other.m_public->t()) {
      return false;
   }
   if(m_public->code_length() != other.m_public->code_length()) {
      return false;
   }
   return true;
}

namespace {

class MCE_KEM_Encryptor final : public PK_Ops::KEM_Encryption_with_KDF {
   public:
      MCE_KEM_Encryptor(std::shared_ptr<const McEliece_PublicKeyInternal> key, std::string_view kdf) :
            KEM_Encryption_with_KDF(kdf), m_key(std::move(key)) {}

   private:
      size_t raw_kem_shared_key_length() const override {
         const size_t err_sz = (m_key->code_length() + 7) / 8;
         const size_t ptext_sz = (m_key->message_word_bit_length() + 7) / 8;
         return ptext_sz + err_sz;
      }

      size_t encapsulated_key_length() const override { return (m_key->code_length() + 7) / 8; }

      void raw_kem_encrypt(std::span<uint8_t> out_encapsulated_key,
                           std::span<uint8_t> raw_shared_key,
                           RandomNumberGenerator& rng) override {
         secure_vector<uint8_t> plaintext = m_key->random_plaintext_element(rng);

         secure_vector<uint8_t> ciphertext;
         secure_vector<uint8_t> error_mask;
         mceliece_encrypt(ciphertext, error_mask, plaintext, *m_key, rng);

         // TODO: Perhaps avoid the copies below
         BOTAN_ASSERT_NOMSG(out_encapsulated_key.size() == ciphertext.size());
         std::copy(ciphertext.begin(), ciphertext.end(), out_encapsulated_key.begin());

         BOTAN_ASSERT_NOMSG(raw_shared_key.size() == plaintext.size() + error_mask.size());
         BufferStuffer bs(raw_shared_key);
         bs.append(plaintext);
         bs.append(error_mask);
      }

      std::shared_ptr<const McEliece_PublicKeyInternal> m_key;
};

class MCE_KEM_Decryptor final : public PK_Ops::KEM_Decryption_with_KDF {
   public:
      MCE_KEM_Decryptor(std::shared_ptr<const McEliece_PrivateKeyInternal> key, std::string_view kdf) :
            KEM_Decryption_with_KDF(kdf), m_key(std::move(key)) {}

   private:
      size_t raw_kem_shared_key_length() const override {
         const size_t err_sz = (m_key->code_length() + 7) / 8;
         const size_t ptext_sz = (m_key->message_word_bit_length() + 7) / 8;
         return ptext_sz + err_sz;
      }

      size_t encapsulated_key_length() const override { return (m_key->code_length() + 7) / 8; }

      void raw_kem_decrypt(std::span<uint8_t> out_shared_key, std::span<const uint8_t> encapsulated_key) override {
         secure_vector<uint8_t> plaintext;
         secure_vector<uint8_t> error_mask;
         mceliece_decrypt(plaintext, error_mask, encapsulated_key.data(), encapsulated_key.size(), *m_key);

         // TODO: perhaps avoid the copies below
         BOTAN_ASSERT_NOMSG(out_shared_key.size() == plaintext.size() + error_mask.size());
         BufferStuffer bs(out_shared_key);
         bs.append(plaintext);
         bs.append(error_mask);
      }

      std::shared_ptr<const McEliece_PrivateKeyInternal> m_key;
};

}  // namespace

std::unique_ptr<Private_Key> McEliece_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<McEliece_PrivateKey>(rng, get_code_length(), get_t());
}

std::unique_ptr<PK_Ops::KEM_Encryption> McEliece_PublicKey::create_kem_encryption_op(std::string_view params,
                                                                                     std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<MCE_KEM_Encryptor>(m_public, params);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::KEM_Decryption> McEliece_PrivateKey::create_kem_decryption_op(RandomNumberGenerator& /*rng*/,
                                                                                      std::string_view params,
                                                                                      std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<MCE_KEM_Decryptor>(m_private, params);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan
