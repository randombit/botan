/*
* Ed25519
* (C) 2017 Ribose Inc
*     2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ED25519_H_
#define BOTAN_ED25519_H_

#include <botan/pk_keys.h>
#include <span>

namespace Botan {

class BOTAN_PUBLIC_API(2, 2) Ed25519_PublicKey : public virtual Public_Key {
   public:
      std::string algo_name() const override { return "Ed25519"; }

      size_t estimated_strength() const override { return 128; }

      size_t key_length() const override { return 255; }

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

      AlgorithmIdentifier algorithm_identifier() const override;

      std::vector<uint8_t> raw_public_key_bits() const override;

      std::vector<uint8_t> public_key_bits() const override;

      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator& rng) const final;

      bool supports_operation(PublicKeyOperation op) const override { return (op == PublicKeyOperation::Signature); }

      BOTAN_DEPRECATED("Use raw_public_key_bits") const std::vector<uint8_t>& get_public_key() const {
         return m_public;
      }

      /**
      * Create a Ed25519 Public Key.
      * @param alg_id the X.509 algorithm identifier
      * @param key_bits DER encoded public key bits
      */
      Ed25519_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits);

      // NOLINTNEXTLINE(*-explicit-conversions) TODO(Botan4) make this constructor explicit
      Ed25519_PublicKey(std::span<const uint8_t> pub) : Ed25519_PublicKey(pub.data(), pub.size()) {}

      Ed25519_PublicKey(const uint8_t pub_key[], size_t len);

      std::unique_ptr<PK_Ops::Verification> create_verification_op(std::string_view params,
                                                                   std::string_view provider) const override;

      std::unique_ptr<PK_Ops::Verification> create_x509_verification_op(const AlgorithmIdentifier& signature_algorithm,
                                                                        std::string_view provider) const override;

   protected:
      Ed25519_PublicKey() = default;
      std::vector<uint8_t> m_public;  // NOLINT(*non-private-member-variable*)
};

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

class BOTAN_PUBLIC_API(2, 2) Ed25519_PrivateKey final : public Ed25519_PublicKey,
                                                        public virtual Private_Key {
   public:
      /**
      * Construct a private key from the specified parameters.
      * @param alg_id the X.509 algorithm identifier
      * @param key_bits PKCS #8 structure
      */
      Ed25519_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits);

      /**
      * Generate a new random private key.
      * @param rng the RNG to use
      */
      explicit Ed25519_PrivateKey(RandomNumberGenerator& rng);

      /**
      * Construct a private key from the specified parameters.
      *
      * @param secret_key the private key
      *
      * The behavior of this function depends on the input length.
      *
      * If the input is 32 bytes long then it is treated as a seed, and a new
      * keypair is generated.
      *
      * If the input is 64 bytes long then it is treated as a pair of 32 byte
      * values, first the private key and then the public key.
      *
      * This constructor is deprecated since the above behavior is
      * quite surprising. If you are relying on it, please comment in #4666.
      */
      BOTAN_DEPRECATED("Use from_seed or from_bytes") explicit Ed25519_PrivateKey(std::span<const uint8_t> secret_key);

      /**
      * Generate a new Ed25519_PrivateKey from the provided 32-byte seed
      */
      static Ed25519_PrivateKey from_seed(std::span<const uint8_t> seed);

      /**
      * Decode the Ed25519_PrivateKey from the provided 64-byte value
      *
      * The first 32 bytes are the private key and the last 32 bytes
      * are the precomputed public key.
      */
      static Ed25519_PrivateKey from_bytes(std::span<const uint8_t> bytes);

      BOTAN_DEPRECATED("Use raw_private_key_bits") const secure_vector<uint8_t>& get_private_key() const {
         return m_private;
      }

      secure_vector<uint8_t> raw_private_key_bits() const override { return m_private; }

      secure_vector<uint8_t> private_key_bits() const override;

      std::unique_ptr<Public_Key> public_key() const override;

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

      std::unique_ptr<PK_Ops::Signature> create_signature_op(RandomNumberGenerator& rng,
                                                             std::string_view params,
                                                             std::string_view provider) const override;

   private:
      secure_vector<uint8_t> m_private;
};

BOTAN_DIAGNOSTIC_POP

BOTAN_DEPRECATED("Use Ed25519_PrivateKey or Sodium::crypto_sign_ed25519_seed_keypair")
void ed25519_gen_keypair(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[32]);

BOTAN_DEPRECATED("Use Ed25519_PrivateKey or Sodium::crypto_sign_ed25519_detached")
void ed25519_sign(uint8_t sig[64],
                  const uint8_t msg[],
                  size_t msg_len,
                  const uint8_t sk[64],
                  const uint8_t domain_sep[],
                  size_t domain_sep_len);

BOTAN_DEPRECATED("Use Ed25519_PublicKey or Sodium::crypto_sign_ed25519_verify_detached")
bool ed25519_verify(const uint8_t msg[],
                    size_t msg_len,
                    const uint8_t sig[64],
                    const uint8_t pk[32],
                    const uint8_t domain_sep[],
                    size_t domain_sep_len);

}  // namespace Botan

#endif
