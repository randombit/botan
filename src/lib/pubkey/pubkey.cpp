/*
* (C) 1999-2010,2015,2018,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pubkey.h>

#include <botan/ber_dec.h>
#include <botan/bigint.h>
#include <botan/der_enc.h>
#include <botan/pk_ops.h>
#include <botan/rng.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/fmt.h>

namespace Botan {

secure_vector<uint8_t> PK_Decryptor::decrypt(const uint8_t in[], size_t length) const {
   uint8_t valid_mask = 0;

   secure_vector<uint8_t> decoded = do_decrypt(valid_mask, in, length);

   if(valid_mask == 0) {
      throw Decoding_Error("Invalid public key ciphertext, cannot decrypt");
   }

   return decoded;
}

secure_vector<uint8_t> PK_Decryptor::decrypt_or_random(const uint8_t in[],
                                                       size_t length,
                                                       size_t expected_pt_len,
                                                       RandomNumberGenerator& rng,
                                                       const uint8_t required_content_bytes[],
                                                       const uint8_t required_content_offsets[],
                                                       size_t required_contents_length) const {
   const secure_vector<uint8_t> fake_pms = rng.random_vec(expected_pt_len);

   uint8_t decrypt_valid = 0;
   secure_vector<uint8_t> decoded = do_decrypt(decrypt_valid, in, length);

   auto valid_mask = CT::Mask<uint8_t>::is_equal(decrypt_valid, 0xFF);
   valid_mask &= CT::Mask<uint8_t>(CT::Mask<size_t>::is_zero(decoded.size() ^ expected_pt_len));

   decoded.resize(expected_pt_len);

   for(size_t i = 0; i != required_contents_length; ++i) {
      /*
      These values are chosen by the application and for TLS are constants,
      so this early failure via assert is fine since we know 0,1 < 48

      If there is a protocol that has content checks on the key where
      the expected offsets are controllable by the attacker this could
      still leak.

      Alternately could always reduce the offset modulo the length?
      */

      const uint8_t exp = required_content_bytes[i];
      const uint8_t off = required_content_offsets[i];

      BOTAN_ASSERT(off < expected_pt_len, "Offset in range of plaintext");

      auto eq = CT::Mask<uint8_t>::is_equal(decoded[off], exp);

      valid_mask &= eq;
   }

   // If valid_mask is false, assign fake pre master instead
   valid_mask.select_n(decoded.data(), decoded.data(), fake_pms.data(), expected_pt_len);

   return decoded;
}

secure_vector<uint8_t> PK_Decryptor::decrypt_or_random(const uint8_t in[],
                                                       size_t length,
                                                       size_t expected_pt_len,
                                                       RandomNumberGenerator& rng) const {
   return decrypt_or_random(in, length, expected_pt_len, rng, nullptr, nullptr, 0);
}

PK_Encryptor_EME::PK_Encryptor_EME(const Public_Key& key,
                                   RandomNumberGenerator& rng,
                                   std::string_view padding,
                                   std::string_view provider) {
   m_op = key.create_encryption_op(rng, padding, provider);
   if(!m_op) {
      throw Invalid_Argument(fmt("Key type {} does not support encryption", key.algo_name()));
   }
}

PK_Encryptor_EME::~PK_Encryptor_EME() = default;

PK_Encryptor_EME::PK_Encryptor_EME(PK_Encryptor_EME&&) noexcept = default;
PK_Encryptor_EME& PK_Encryptor_EME::operator=(PK_Encryptor_EME&&) noexcept = default;

size_t PK_Encryptor_EME::ciphertext_length(size_t ptext_len) const {
   return m_op->ciphertext_length(ptext_len);
}

std::vector<uint8_t> PK_Encryptor_EME::enc(const uint8_t in[], size_t length, RandomNumberGenerator& rng) const {
   return m_op->encrypt(std::span{in, length}, rng);
}

size_t PK_Encryptor_EME::maximum_input_size() const {
   return m_op->max_input_bits() / 8;
}

PK_Decryptor_EME::PK_Decryptor_EME(const Private_Key& key,
                                   RandomNumberGenerator& rng,
                                   std::string_view padding,
                                   std::string_view provider) {
   m_op = key.create_decryption_op(rng, padding, provider);
   if(!m_op) {
      throw Invalid_Argument(fmt("Key type {} does not support decryption", key.algo_name()));
   }
}

PK_Decryptor_EME::~PK_Decryptor_EME() = default;

PK_Decryptor_EME::PK_Decryptor_EME(PK_Decryptor_EME&&) noexcept = default;
PK_Decryptor_EME& PK_Decryptor_EME::operator=(PK_Decryptor_EME&&) noexcept = default;

size_t PK_Decryptor_EME::plaintext_length(size_t ctext_len) const {
   return m_op->plaintext_length(ctext_len);
}

secure_vector<uint8_t> PK_Decryptor_EME::do_decrypt(uint8_t& valid_mask, const uint8_t in[], size_t in_len) const {
   return m_op->decrypt(valid_mask, {in, in_len});
}

PK_KEM_Encryptor::PK_KEM_Encryptor(const Public_Key& key, std::string_view param, std::string_view provider) {
   m_op = key.create_kem_encryption_op(param, provider);
   if(!m_op) {
      throw Invalid_Argument(fmt("Key type {} does not support KEM encryption", key.algo_name()));
   }
}

PK_KEM_Encryptor::~PK_KEM_Encryptor() = default;

PK_KEM_Encryptor::PK_KEM_Encryptor(PK_KEM_Encryptor&&) noexcept = default;
PK_KEM_Encryptor& PK_KEM_Encryptor::operator=(PK_KEM_Encryptor&&) noexcept = default;

size_t PK_KEM_Encryptor::shared_key_length(size_t desired_shared_key_len) const {
   return m_op->shared_key_length(desired_shared_key_len);
}

size_t PK_KEM_Encryptor::encapsulated_key_length() const {
   return m_op->encapsulated_key_length();
}

void PK_KEM_Encryptor::encrypt(std::span<uint8_t> out_encapsulated_key,
                               std::span<uint8_t> out_shared_key,
                               RandomNumberGenerator& rng,
                               size_t desired_shared_key_len,
                               std::span<const uint8_t> salt) {
   BOTAN_ARG_CHECK(out_encapsulated_key.size() == encapsulated_key_length(), "not enough space for encapsulated key");
   BOTAN_ARG_CHECK(out_shared_key.size() == shared_key_length(desired_shared_key_len),
                   "not enough space for shared key");
   m_op->kem_encrypt(out_encapsulated_key, out_shared_key, rng, desired_shared_key_len, salt);
}

size_t PK_KEM_Decryptor::shared_key_length(size_t desired_shared_key_len) const {
   return m_op->shared_key_length(desired_shared_key_len);
}

size_t PK_KEM_Decryptor::encapsulated_key_length() const {
   return m_op->encapsulated_key_length();
}

PK_KEM_Decryptor::PK_KEM_Decryptor(const Private_Key& key,
                                   RandomNumberGenerator& rng,
                                   std::string_view param,
                                   std::string_view provider) {
   m_op = key.create_kem_decryption_op(rng, param, provider);
   if(!m_op) {
      throw Invalid_Argument(fmt("Key type {} does not support KEM decryption", key.algo_name()));
   }
}

PK_KEM_Decryptor::~PK_KEM_Decryptor() = default;

PK_KEM_Decryptor::PK_KEM_Decryptor(PK_KEM_Decryptor&&) noexcept = default;
PK_KEM_Decryptor& PK_KEM_Decryptor::operator=(PK_KEM_Decryptor&&) noexcept = default;

void PK_KEM_Decryptor::decrypt(std::span<uint8_t> out_shared_key,
                               std::span<const uint8_t> encap_key,
                               size_t desired_shared_key_len,
                               std::span<const uint8_t> salt) {
   BOTAN_ARG_CHECK(out_shared_key.size() == shared_key_length(desired_shared_key_len),
                   "inconsistent size of shared key output buffer");
   m_op->kem_decrypt(out_shared_key, encap_key, desired_shared_key_len, salt);
}

PK_Key_Agreement::PK_Key_Agreement(const Private_Key& key,
                                   RandomNumberGenerator& rng,
                                   std::string_view kdf,
                                   std::string_view provider) {
   m_op = key.create_key_agreement_op(rng, kdf, provider);
   if(!m_op) {
      throw Invalid_Argument(fmt("Key type {} does not support key agreement", key.algo_name()));
   }
}

PK_Key_Agreement::~PK_Key_Agreement() = default;

PK_Key_Agreement::PK_Key_Agreement(PK_Key_Agreement&&) noexcept = default;
PK_Key_Agreement& PK_Key_Agreement::operator=(PK_Key_Agreement&&) noexcept = default;

size_t PK_Key_Agreement::agreed_value_size() const {
   return m_op->agreed_value_size();
}

SymmetricKey PK_Key_Agreement::derive_key(size_t key_len,
                                          const uint8_t in[],
                                          size_t in_len,
                                          std::string_view params) const {
   return this->derive_key(key_len, in, in_len, cast_char_ptr_to_uint8(params.data()), params.length());
}

SymmetricKey PK_Key_Agreement::derive_key(size_t key_len,
                                          const std::span<const uint8_t> in,
                                          std::string_view params) const {
   return this->derive_key(key_len, in.data(), in.size(), cast_char_ptr_to_uint8(params.data()), params.length());
}

SymmetricKey PK_Key_Agreement::derive_key(
   size_t key_len, const uint8_t in[], size_t in_len, const uint8_t salt[], size_t salt_len) const {
   return SymmetricKey(m_op->agree(key_len, {in, in_len}, {salt, salt_len}));
}

namespace {

void check_der_format_supported(Signature_Format format, size_t parts) {
   if(format != Signature_Format::Standard && parts == 1) {
      throw Invalid_Argument("This algorithm does not support DER encoding");
   }
}

}  // namespace

PK_Signer::PK_Signer(PK_Signature_Options options) {
   // Appease GCC warning about a possibly dangling reference because when using
   // std::reference_wrapper's implicit conversion to the contained reference
   // the wrapper does not outlive the reference which seems to confuse GCC.
   const auto key_wrapped = options.private_key().required();
   const Private_Key& key = key_wrapped.get();

   // TODO: The downstream algorithms should decide whether to require an RNG
   //       (e.g. explicitly 'deterministic' signatures should not require it).
   RandomNumberGenerator& rng = options.rng().required();

   m_op = key._create_signature_op(rng, options);
   if(!m_op) {
      throw Invalid_Argument(fmt("Key type {} does not support signature generation", key.algo_name()));
   }
   m_sig_format = options.using_der_encoded_signature() ? Signature_Format::DerSequence : Signature_Format::Standard;
   m_parts = key.message_parts();
   m_part_size = key.message_part_size();
   check_der_format_supported(m_sig_format, m_parts);

   options.validate_option_consumption();
}

PK_Signer::PK_Signer(const Private_Key& key,
                     RandomNumberGenerator& rng,
                     std::string_view padding,
                     Signature_Format format,
                     std::string_view provider) :
      PK_Signer(PK_Signature_Options_Builder(key, rng, padding, format, provider).commit()) {}

PK_Signer::PK_Signer(const Private_Key& key, RandomNumberGenerator& rng, PK_Signature_Options& options) {
   m_op = key._create_signature_op(rng, options);
   if(!m_op) {
      throw Invalid_Argument(fmt("Key type {} does not support signature generation", key.algo_name()));
   }
   m_sig_format = options.using_der_encoded_signature() ? Signature_Format::DerSequence : Signature_Format::Standard;
   m_parts = key.message_parts();
   m_part_size = key.message_part_size();
   check_der_format_supported(m_sig_format, m_parts);
}

AlgorithmIdentifier PK_Signer::algorithm_identifier() const {
   return m_op->algorithm_identifier();
}

std::string PK_Signer::hash_function() const {
   return m_op->hash_function();
}

PK_Signer::~PK_Signer() = default;

PK_Signer::PK_Signer(PK_Signer&&) noexcept = default;
PK_Signer& PK_Signer::operator=(PK_Signer&&) noexcept = default;

void PK_Signer::update(std::string_view in) {
   this->update(cast_char_ptr_to_uint8(in.data()), in.size());
}

void PK_Signer::update(const uint8_t in[], size_t length) {
   m_op->update({in, length});
}

namespace {

std::vector<uint8_t> der_encode_signature(std::span<const uint8_t> sig, size_t parts, size_t part_size) {
   if(sig.size() % parts != 0 || sig.size() != parts * part_size) {
      throw Encoding_Error("Unexpected size for DER signature");
   }

   BufferSlicer bs_sig(sig);
   std::vector<BigInt> sig_parts;
   sig_parts.reserve(parts);
   for(size_t i = 0; i != parts; ++i) {
      sig_parts.emplace_back(BigInt::from_bytes(bs_sig.take(part_size)));
   }

   std::vector<uint8_t> output;
   DER_Encoder(output).start_sequence().encode_list(sig_parts).end_cons();
   return output;
}

}  // namespace

size_t PK_Signer::signature_length() const {
   if(m_sig_format == Signature_Format::Standard) {
      return m_op->signature_length();
   } else if(m_sig_format == Signature_Format::DerSequence) {
      // This is a large over-estimate but its easier than computing
      // the exact value
      return m_op->signature_length() + (8 + 4 * m_parts);
   } else {
      throw Internal_Error("PK_Signer: Invalid signature format enum");
   }
}

std::vector<uint8_t> PK_Signer::signature(RandomNumberGenerator& rng) {
   std::vector<uint8_t> sig = m_op->sign(rng);

   if(m_sig_format == Signature_Format::Standard) {
      return sig;
   } else if(m_sig_format == Signature_Format::DerSequence) {
      return der_encode_signature(sig, m_parts, m_part_size);
   } else {
      throw Internal_Error("PK_Signer: Invalid signature format enum");
   }
}

PK_Verifier::PK_Verifier(PK_Signature_Options options) {
   // Appease GCC warning about a possibly dangling reference because when using
   // std::reference_wrapper's implicit conversion to the contained reference
   // the wrapper does not outlive the reference which seems to confuse GCC.
   const auto key_wrapped = options.public_key().required();
   const Public_Key& key = key_wrapped.get();
   m_op = key._create_verification_op(options);
   if(!m_op) {
      throw Invalid_Argument(fmt("Key type {} does not support signature verification", key.algo_name()));
   }
   m_sig_format = options.using_der_encoded_signature() ? Signature_Format::DerSequence : Signature_Format::Standard;
   m_parts = key.message_parts();
   m_part_size = key.message_part_size();
   check_der_format_supported(m_sig_format, m_parts);

   options.validate_option_consumption();
}

PK_Verifier::PK_Verifier(const Public_Key& pub_key,
                         std::string_view padding,
                         Signature_Format format,
                         std::string_view provider) :
      PK_Verifier(PK_Verification_Options_Builder(pub_key, padding, format, provider).commit()) {}

PK_Verifier::PK_Verifier(const Public_Key& key, PK_Signature_Options& options) {
   m_op = key._create_verification_op(options);
   if(!m_op) {
      throw Invalid_Argument(fmt("Key type {} does not support signature verification", key.algo_name()));
   }
   m_sig_format = options.using_der_encoded_signature() ? Signature_Format::DerSequence : Signature_Format::Standard;
   m_parts = key.message_parts();
   m_part_size = key.message_part_size();
   check_der_format_supported(m_sig_format, m_parts);
}

PK_Verifier::PK_Verifier(const Public_Key& key,
                         const AlgorithmIdentifier& signature_algorithm,
                         std::string_view provider) {
   m_op = key.create_x509_verification_op(signature_algorithm, provider);

   if(!m_op) {
      throw Invalid_Argument(fmt("Key type {} does not support X.509 signature verification", key.algo_name()));
   }

   m_sig_format = key.default_x509_signature_format();
   m_parts = key.message_parts();
   m_part_size = key.message_part_size();
   check_der_format_supported(m_sig_format, m_parts);
}

PK_Verifier::~PK_Verifier() = default;

PK_Verifier::PK_Verifier(PK_Verifier&&) noexcept = default;
PK_Verifier& PK_Verifier::operator=(PK_Verifier&&) noexcept = default;

std::string PK_Verifier::hash_function() const {
   return m_op->hash_function();
}

void PK_Verifier::set_input_format(Signature_Format format) {
   check_der_format_supported(format, m_parts);
   m_sig_format = format;
}

bool PK_Verifier::verify_message(const uint8_t msg[], size_t msg_length, const uint8_t sig[], size_t sig_length) {
   update(msg, msg_length);
   return check_signature(sig, sig_length);
}

void PK_Verifier::update(std::string_view in) {
   this->update(cast_char_ptr_to_uint8(in.data()), in.size());
}

void PK_Verifier::update(const uint8_t in[], size_t length) {
   m_op->update({in, length});
}

namespace {

std::vector<uint8_t> decode_der_signature(const uint8_t sig[], size_t length, size_t sig_parts, size_t sig_part_size) {
   std::vector<uint8_t> real_sig;
   BER_Decoder decoder(sig, length);
   BER_Decoder ber_sig = decoder.start_sequence();

   BOTAN_ASSERT_NOMSG(sig_parts != 0 && sig_part_size != 0);

   size_t count = 0;

   while(ber_sig.more_items()) {
      BigInt sig_part;
      ber_sig.decode(sig_part);
      real_sig += sig_part.serialize(sig_part_size);
      ++count;
   }

   if(count != sig_parts) {
      throw Decoding_Error("PK_Verifier: signature size invalid");
   }

   const std::vector<uint8_t> reencoded = der_encode_signature(real_sig, sig_parts, sig_part_size);

   if(reencoded.size() != length || CT::is_equal(reencoded.data(), sig, reencoded.size()).as_bool() == false) {
      throw Decoding_Error("PK_Verifier: signature is not the canonical DER encoding");
   }
   return real_sig;
}

}  // namespace

bool PK_Verifier::check_signature(const uint8_t sig[], size_t length) {
   try {
      if(m_sig_format == Signature_Format::Standard) {
         return m_op->is_valid_signature({sig, length});
      } else if(m_sig_format == Signature_Format::DerSequence) {
         bool decoding_success = false;
         std::vector<uint8_t> real_sig;

         try {
            real_sig = decode_der_signature(sig, length, m_parts, m_part_size);
            decoding_success = true;
         } catch(Decoding_Error&) {}

         bool accept = m_op->is_valid_signature(real_sig);

         return accept && decoding_success;
      } else {
         throw Internal_Error("PK_Verifier: Invalid signature format enum");
      }
   } catch(Invalid_Argument&) {
      return false;
   } catch(Decoding_Error&) {
      return false;
   } catch(Encoding_Error&) {
      return false;
   }
}

}  // namespace Botan
