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

#include <array>
#include <utility>

namespace Botan {

namespace {

enum class McEliece_Key_Source : uint8_t { Raw, Encoded };

constexpr std::array<std::pair<size_t, size_t>, 6> MCE_SUPPORTED_PARAMS = {
   {{1632, 33}, {2480, 45}, {2960, 57}, {3408, 67}, {4624, 95}, {6624, 115}}};

bool mceliece_params_are_supported(size_t code_length, size_t t) {
   for(const auto& [supported_n, supported_t] : MCE_SUPPORTED_PARAMS) {
      if(code_length == supported_n && t == supported_t) {
         return true;
      }
   }
   return false;
}

[[noreturn]] void throw_mceliece_validation_error(McEliece_Key_Source source, const char* msg) {
   if(source == McEliece_Key_Source::Encoded) {
      throw Decoding_Error(msg);
   } else {
      throw Invalid_Argument(msg);
   }
}

McEliece_Params mceliece_validate_params(size_t code_length, size_t t, McEliece_Key_Source source) {
   if(!mceliece_params_are_supported(code_length, t)) {
      throw_mceliece_validation_error(source, "Unsupported McEliece parameters");
   }

   const size_t ext_deg = ceil_log2(code_length);
   if(ext_deg < 2 || ext_deg > 15) {
      throw_mceliece_validation_error(source, "McEliece code length out of supported range");
   }

   const size_t codimension = ext_deg * t;
   if(codimension >= code_length) {
      throw_mceliece_validation_error(source, "McEliece parameters are inconsistent");
   }

   const size_t dimension = code_length - codimension;
   const size_t words_per_matrix_row = bit_size_to_32bit_size(codimension);
   const size_t public_matrix_bytes = dimension * words_per_matrix_row * sizeof(uint32_t);

   return McEliece_Params{code_length, t, ext_deg, codimension, dimension, words_per_matrix_row, public_matrix_bytes};
}

uint32_t padding_mask(size_t bit_count) {
   const size_t used_bits = bit_count % 32;
   if(used_bits == 0) {
      return 0;
   }
   return ~((static_cast<uint32_t>(1) << used_bits) - 1);
}

void validate_public_matrix(const std::vector<uint8_t>& public_matrix,
                            const McEliece_Params& params,
                            McEliece_Key_Source source) {
   if(public_matrix.size() != params.public_matrix_bytes) {
      throw_mceliece_validation_error(source, "McEliece public matrix size does not match parameters");
   }

   const uint32_t unused_bits_mask = padding_mask(params.codimension);
   if(unused_bits_mask == 0) {
      return;
   }

   const size_t row_bytes = params.words_per_matrix_row * sizeof(uint32_t);
   const size_t final_word_offset = (params.words_per_matrix_row - 1) * sizeof(uint32_t);
   for(size_t row = 0; row != params.dimension; ++row) {
      const uint8_t* row_ptr = public_matrix.data() + row * row_bytes;
      const uint32_t final_word = load_le<uint32_t>(row_ptr + final_word_offset, 0);
      if((final_word & unused_bits_mask) != 0) {
         throw_mceliece_validation_error(source, "McEliece public matrix contains non-zero padding bits");
      }
   }
}

void validate_polynomial(const polyn_gf2m& polyn,
                         const McEliece_Params& params,
                         size_t min_coeff_count,
                         size_t max_degree,
                         McEliece_Key_Source source) {
   const std::shared_ptr<GF2m_Field> field = polyn.get_sp_field();
   if(!field || field->get_extension_degree() != params.ext_deg) {
      throw_mceliece_validation_error(source, "McEliece polynomial uses an inconsistent field");
   }

   if(polyn.get_coeff_count() < min_coeff_count) {
      throw_mceliece_validation_error(source, "McEliece polynomial has too few coefficients");
   }

   const int degree = polyn.get_degree();
   if(degree >= 0 && static_cast<size_t>(degree) > max_degree) {
      throw_mceliece_validation_error(source, "McEliece polynomial degree is too large");
   }

   const size_t field_cardinality = static_cast<size_t>(1) << params.ext_deg;
   for(size_t i = 0; i != polyn.get_coeff_count(); ++i) {
      if(polyn.get_coef(i) >= field_cardinality) {
         throw_mceliece_validation_error(source, "McEliece polynomial coefficient is out of range");
      }
   }
}

void validate_support_inverse(const std::vector<gf2m>& inverse_support,
                              const McEliece_Params& params,
                              McEliece_Key_Source source) {
   if(inverse_support.size() != params.code_length) {
      throw_mceliece_validation_error(source, "McEliece support size does not match code length");
   }

   std::vector<uint8_t> seen(params.code_length);
   for(const gf2m support_elem : inverse_support) {
      if(support_elem >= params.code_length) {
         throw_mceliece_validation_error(source, "McEliece support element is out of range");
      }
      if(seen[support_elem] != 0) {
         throw_mceliece_validation_error(source, "McEliece support is not a permutation");
      }
      seen[support_elem] = 1;
   }
}

void validate_parity_check_matrix(const std::vector<uint32_t>& parity_check_matrix_coeffs,
                                  const McEliece_Params& params,
                                  McEliece_Key_Source source) {
   if(parity_check_matrix_coeffs.size() != params.words_per_matrix_row * params.code_length) {
      throw_mceliece_validation_error(source, "McEliece parity check matrix has wrong length");
   }

   const uint32_t unused_bits_mask = padding_mask(params.codimension);
   if(unused_bits_mask == 0) {
      return;
   }

   for(size_t row = 0; row != params.code_length; ++row) {
      const uint32_t final_word =
         parity_check_matrix_coeffs[row * params.words_per_matrix_row + params.words_per_matrix_row - 1];
      if((final_word & unused_bits_mask) != 0) {
         throw_mceliece_validation_error(source, "McEliece parity check matrix contains non-zero padding bits");
      }
   }
}

void validate_private_components(const polyn_gf2m& goppa_polyn,
                                 const std::vector<uint32_t>& parity_check_matrix_coeffs,
                                 const std::vector<polyn_gf2m>& square_root_matrix,
                                 const std::vector<gf2m>& inverse_support,
                                 const std::vector<uint8_t>& public_matrix,
                                 const McEliece_Params& params,
                                 McEliece_Key_Source source) {
   validate_public_matrix(public_matrix, params, source);

   if(goppa_polyn.get_degree() != static_cast<int>(params.t)) {
      throw_mceliece_validation_error(source, "degree of decoded Goppa polynomial is incorrect");
   }
   validate_polynomial(goppa_polyn, params, params.t + 1, params.t, source);
   if(goppa_polyn.get_lead_coef() != 1) {
      throw_mceliece_validation_error(source, "McEliece Goppa polynomial is not monic");
   }

   if(square_root_matrix.size() != params.t / 2) {
      throw_mceliece_validation_error(source, "McEliece square root matrix has wrong length");
   }
   for(const auto& sqrt_polyn : square_root_matrix) {
      validate_polynomial(sqrt_polyn, params, params.t, params.t - 1, source);
   }

   validate_support_inverse(inverse_support, params, source);
   validate_parity_check_matrix(parity_check_matrix_coeffs, params, source);
}

}  // namespace

McEliece_Params mceliece_validate_keygen_params(size_t code_length, size_t t) {
   return mceliece_validate_params(code_length, t, McEliece_Key_Source::Raw);
}

McEliece_Params mceliece_validate_key_encoding_params(size_t code_length, size_t t) {
   return mceliece_validate_params(code_length, t, McEliece_Key_Source::Encoded);
}

McEliece_PrivateKey::McEliece_PrivateKey(const McEliece_PrivateKey&) = default;
McEliece_PrivateKey::McEliece_PrivateKey(McEliece_PrivateKey&&) noexcept = default;
McEliece_PrivateKey& McEliece_PrivateKey::operator=(const McEliece_PrivateKey&) = default;
McEliece_PrivateKey& McEliece_PrivateKey::operator=(McEliece_PrivateKey&&) noexcept = default;
McEliece_PrivateKey::~McEliece_PrivateKey() = default;

McEliece_PrivateKey::McEliece_PrivateKey(const polyn_gf2m& goppa_polyn,
                                         const std::vector<uint32_t>& parity_check_matrix_coeffs,
                                         const std::vector<polyn_gf2m>& square_root_matrix,
                                         const std::vector<gf2m>& inverse_support,
                                         const std::vector<uint8_t>& public_matrix) {
   const int goppa_degree = goppa_polyn.get_degree();
   if(goppa_degree <= 0) {
      throw Invalid_Argument("invalid McEliece Goppa polynomial degree");
   }

   const McEliece_Params params = mceliece_validate_keygen_params(inverse_support.size(), goppa_degree);
   validate_private_components(goppa_polyn,
                               parity_check_matrix_coeffs,
                               square_root_matrix,
                               inverse_support,
                               public_matrix,
                               params,
                               McEliece_Key_Source::Raw);

   m_public = std::make_shared<const McEliece_PublicKeyInternal>(public_matrix, params.t, params.code_length);
   m_private = std::make_shared<const McEliece_PrivateKeyInternal>(std::vector<polyn_gf2m>{goppa_polyn},
                                                                   square_root_matrix,
                                                                   inverse_support,
                                                                   parity_check_matrix_coeffs,
                                                                   params.codimension,
                                                                   params.dimension);
}

// NOLINTNEXTLINE(*-member-init)
McEliece_PrivateKey::McEliece_PrivateKey(RandomNumberGenerator& rng, size_t code_length, size_t t) {
   const McEliece_Params params = mceliece_validate_keygen_params(code_length, t);
   *this = generate_mceliece_key(rng, params.ext_deg, code_length, t);
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

McEliece_PublicKey::McEliece_PublicKey(const std::vector<uint8_t>& pub_matrix, size_t t, size_t the_code_length) {
   const McEliece_Params params = mceliece_validate_keygen_params(the_code_length, t);
   validate_public_matrix(pub_matrix, params, McEliece_Key_Source::Raw);
   m_public = std::make_shared<const McEliece_PublicKeyInternal>(pub_matrix, t, the_code_length);
}

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

bool McEliece_PublicKey::check_key(RandomNumberGenerator& /*rng*/, bool /*strong*/) const {
   try {
      if(!m_public) {
         return false;
      }

      const McEliece_Params params = mceliece_validate_keygen_params(m_public->code_length(), m_public->t());
      validate_public_matrix(m_public->public_matrix(), params, McEliece_Key_Source::Raw);
      return true;
   } catch(...) {
      return false;
   }
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

   const McEliece_Params params = mceliece_validate_key_encoding_params(n, t);
   validate_public_matrix(public_matrix, params, McEliece_Key_Source::Encoded);

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

   const McEliece_Params params = mceliece_validate_key_encoding_params(n, t);
   validate_public_matrix(public_matrix, params, McEliece_Key_Source::Encoded);

   auto sp_field = std::make_shared<GF2m_Field>(params.ext_deg);
   std::vector<polyn_gf2m> g = {polyn_gf2m(enc_g, sp_field)};
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
   if(enc_H.size() / 4 != params.words_per_matrix_row * n) {
      throw Decoding_Error("encoded parity check matrix has wrong length");
   }

   std::vector<uint32_t> coeffs;
   for(uint32_t i = 0; i < enc_H.size(); i += 4) {
      coeffs.push_back(make_uint32(enc_H[i], enc_H[i + 1], enc_H[i + 2], enc_H[i + 3]));
   }

   validate_private_components(g[0], coeffs, sqrtmod, Linv, public_matrix, params, McEliece_Key_Source::Encoded);

   m_public = std::make_shared<const McEliece_PublicKeyInternal>(std::move(public_matrix), t, n);
   m_private = std::make_shared<const McEliece_PrivateKeyInternal>(
      std::move(g), std::move(sqrtmod), std::move(Linv), std::move(coeffs), params.codimension, params.dimension);
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

std::unique_ptr<PK_Ops::KEM_Encryption> McEliece_PublicKey::create_kem_encryption_op(
   std::string_view params, std::string_view provider, RandomNumberGenerator* /*rng_may_be_null*/) const {
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
