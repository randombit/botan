/*
 * HQC key encapsulation mechanism
 *
 * Wraps the Rust implementation in the crate rust-hqc via its C API.
 *
 * (C) 2026 Falko Strenzke
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/hqc.h>

#include <botan/assert.h>
#include <botan/pubkey.h>
#include <botan/rng.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/hqc_ffi.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/pk_options_impl.h>

namespace Botan {

namespace {

/// Length of the seed at the start of an encapsulation key
constexpr size_t HQC_EK_SEED_BYTES = 32;

}  // namespace

class HQC_PublicKeyInternal final {
   public:
      HQC_PublicKeyInternal(HQC_Mode mode, std::vector<uint8_t> ek) :
            m_mode(mode), m_sizes(HQC_FFI::sizes(mode)), m_ek(std::move(ek)) {
         if(m_ek.size() != m_sizes.ek) {
            throw Invalid_Argument("HQC public key does not have the correct byte count");
         }

         // ek = seed || s, where s is a vector of n bits packed least
         // significant bit first into ceil(n / 8) bytes. The unused high
         // bits of the last byte must be zero.
         const size_t n = m_mode.code_length();
         BOTAN_ASSERT_NOMSG(m_sizes.ek == HQC_EK_SEED_BYTES + (n + 7) / 8);

         const size_t valid_bits_in_last_byte = n % 8;
         if(valid_bits_in_last_byte != 0) {
            const auto padding_mask = static_cast<uint8_t>(0xFF << valid_bits_in_last_byte);
            if((m_ek.back() & padding_mask) != 0) {
               throw Invalid_Argument("HQC public key has non-zero padding bits");
            }
         }
      }

      const HQC_Mode& mode() const { return m_mode; }

      const HQC_FFI::Sizes& sizes() const { return m_sizes; }

      const std::vector<uint8_t>& ek() const { return m_ek; }

   private:
      HQC_Mode m_mode;
      HQC_FFI::Sizes m_sizes;
      std::vector<uint8_t> m_ek;
};

class HQC_PrivateKeyInternal final {
   public:
      explicit HQC_PrivateKeyInternal(secure_vector<uint8_t> dk) : m_dk(std::move(dk)) {}

      const secure_vector<uint8_t>& dk() const { return m_dk; }

      constexpr void _const_time_poison() const { CT::poison(m_dk); }

      constexpr void _const_time_unpoison() const { CT::unpoison(m_dk); }

   private:
      secure_vector<uint8_t> m_dk;
};

//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//

namespace {

class HQC_KEM_Encryptor final : public PK_Ops::KEM_Encryption_with_KDF {
   public:
      // The shared secret is an output of the hash function G, so it can be used directly
      HQC_KEM_Encryptor(std::shared_ptr<const HQC_PublicKeyInternal> key, const PK_KEM_Options_Reader& options) :
            KEM_Encryption_with_KDF(options, PK_Ops::KemSharedKeyQuality::IsUniform), m_public_key(std::move(key)) {}

      size_t raw_kem_shared_key_length() const override { return m_public_key->sizes().ss; }

      size_t encapsulated_key_length() const override { return m_public_key->sizes().ct; }

      void raw_kem_encrypt(std::span<uint8_t> out_encapsulated_key,
                           std::span<uint8_t> out_shared_key,
                           RandomNumberGenerator& rng) override {
         const auto seed = rng.random_vec<secure_vector<uint8_t>>(HQC_FFI::seed_length);
         CT::poison(seed);

         HQC_FFI::encaps(m_public_key->mode(), out_encapsulated_key, out_shared_key, m_public_key->ek(), seed);

         CT::unpoison_all(out_encapsulated_key, out_shared_key);
      }

   private:
      std::shared_ptr<const HQC_PublicKeyInternal> m_public_key;
};

class HQC_KEM_Decryptor final : public PK_Ops::KEM_Decryption_with_KDF {
   public:
      HQC_KEM_Decryptor(std::shared_ptr<const HQC_PublicKeyInternal> public_key,
                        std::shared_ptr<const HQC_PrivateKeyInternal> private_key,
                        const PK_KEM_Options_Reader& options) :
            KEM_Decryption_with_KDF(options, PK_Ops::KemSharedKeyQuality::IsUniform),
            m_public_key(std::move(public_key)),
            m_private_key(std::move(private_key)) {}

      size_t raw_kem_shared_key_length() const override { return m_public_key->sizes().ss; }

      size_t encapsulated_key_length() const override { return m_public_key->sizes().ct; }

      void raw_kem_decrypt(std::span<uint8_t> out_shared_key, std::span<const uint8_t> encapsulated_key) override {
         if(encapsulated_key.size() != m_public_key->sizes().ct) {
            throw Invalid_Argument("HQC ciphertext does not have the correct byte count");
         }

         auto scope = CT::scoped_poison(*m_private_key);

         // Implicit rejection: an invalid ciphertext results in a pseudo-random
         // shared secret; the C API only signals structurally wrong inputs.
         HQC_FFI::decaps(m_public_key->mode(), out_shared_key, encapsulated_key, m_private_key->dk());

         CT::unpoison(out_shared_key);
      }

   private:
      std::shared_ptr<const HQC_PublicKeyInternal> m_public_key;
      std::shared_ptr<const HQC_PrivateKeyInternal> m_private_key;
};

}  // namespace

//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//

HQC_PublicKey::HQC_PublicKey(std::span<const uint8_t> pub_key, HQC_Mode mode) :
      m_public(std::make_shared<HQC_PublicKeyInternal>(mode, std::vector<uint8_t>(pub_key.begin(), pub_key.end()))) {}

HQC_PublicKey::HQC_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) :
      HQC_PublicKey(key_bits, HQC_Mode(alg_id.oid())) {
   // The parameter set is identified by the OID; no parameters are defined.
   if(!alg_id.parameters_are_empty()) {
      throw Decoding_Error("Unexpected parameters for HQC public key");
   }
}

AlgorithmIdentifier HQC_PublicKey::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

OID HQC_PublicKey::object_identifier() const {
   return m_public->mode().object_identifier();
}

size_t HQC_PublicKey::key_length() const {
   return m_public->mode().code_length();
}

size_t HQC_PublicKey::estimated_strength() const {
   return m_public->mode().estimated_strength();
}

std::vector<uint8_t> HQC_PublicKey::raw_public_key_bits() const {
   return m_public->ek();
}

std::vector<uint8_t> HQC_PublicKey::public_key_bits() const {
   // Currently, there isn't a finalized definition of an ASN.1 structure for
   // HQC public keys. Therefore, we return the raw public key bits.
   return raw_public_key_bits();
}

bool HQC_PublicKey::check_key(RandomNumberGenerator& /*rng*/, bool /*strong*/) const {
   // The public key consists of (seed, s) where s is a vector over GF(2) of
   // the code length. Length validation is performed in the constructor;
   // there are no further structural checks to perform.
   return true;
}

std::unique_ptr<Private_Key> HQC_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<HQC_PrivateKey>(rng, m_public->mode());
}

std::unique_ptr<PK_Ops::KEM_Encryption> HQC_PublicKey::_create_kem_encryption_op(
   const PK_KEM_Options_Reader& options) const {
   require_software_provider(options, algo_name());

   return std::make_unique<HQC_KEM_Encryptor>(m_public, options);
}

//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//

HQC_PrivateKey::HQC_PrivateKey(RandomNumberGenerator& rng, HQC_Mode mode) {
   const auto sizes = HQC_FFI::sizes(mode);

   const auto seed = rng.random_vec<secure_vector<uint8_t>>(HQC_FFI::seed_length);
   std::vector<uint8_t> ek(sizes.ek);
   secure_vector<uint8_t> dk(sizes.dk);

   CT::poison_all(seed, dk);

   HQC_FFI::keypair(mode, ek, dk, seed);

   CT::unpoison_all(ek, dk);

   m_public = std::make_shared<HQC_PublicKeyInternal>(mode, std::move(ek));
   m_private = std::make_shared<HQC_PrivateKeyInternal>(std::move(dk));
}

HQC_PrivateKey::HQC_PrivateKey(std::span<const uint8_t> sk, HQC_Mode mode) {
   const auto sizes = HQC_FFI::sizes(mode);

   if(sk.size() != sizes.dk) {
      throw Invalid_Argument("HQC private key does not have the correct byte count");
   }

   // The decapsulation key starts with the encapsulation key
   const auto ek = sk.first(sizes.ek);

   m_public = std::make_shared<HQC_PublicKeyInternal>(mode, std::vector<uint8_t>(ek.begin(), ek.end()));
   m_private = std::make_shared<HQC_PrivateKeyInternal>(secure_vector<uint8_t>(sk.begin(), sk.end()));
}

HQC_PrivateKey::HQC_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) :
      HQC_PrivateKey(key_bits, HQC_Mode(alg_id.oid())) {
   // The parameter set is identified by the OID; no parameters are defined.
   if(!alg_id.parameters_are_empty()) {
      throw Decoding_Error("Unexpected parameters for HQC private key");
   }
}

std::unique_ptr<Public_Key> HQC_PrivateKey::public_key() const {
   return std::make_unique<HQC_PublicKey>(*this);
}

bool HQC_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   if(!HQC_PublicKey::check_key(rng, strong)) {
      return false;
   }

   if(strong) {
      PK_KEM_Encryptor enc(*this, "Raw");
      PK_KEM_Decryptor dec(*this, rng, "Raw");
      const auto [c, K] = KEM_Encapsulation::destructure(enc.encrypt(rng));
      const auto K_prime = dec.decrypt(c);
      return K == K_prime;
   }

   return true;
}

secure_vector<uint8_t> HQC_PrivateKey::private_key_bits() const {
   // Currently, there isn't a finalized definition of an ASN.1 structure for
   // HQC private keys. Therefore, we return the raw private key bits.
   return raw_private_key_bits();
}

secure_vector<uint8_t> HQC_PrivateKey::raw_private_key_bits() const {
   return m_private->dk();
}

std::unique_ptr<PK_Ops::KEM_Decryption> HQC_PrivateKey::_create_kem_decryption_op(
   RandomNumberGenerator& rng, const PK_KEM_Options_Reader& options) const {
   BOTAN_UNUSED(rng);
   require_software_provider(options, algo_name());

   return std::make_unique<HQC_KEM_Decryptor>(m_public, m_private, options);
}

}  // namespace Botan
