/*
* Crystals Dilithium Digital Signature Algorithms
* Based on the public domain reference implementation by the
* designers (https://github.com/pq-crystals/dilithium)
*
* Further changes
* (C) 2021-2023 Jack Lloyd
* (C) 2021-2022 Manuel Glaser - Rohde & Schwarz Cybersecurity
* (C) 2021-2023 Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DILITHIUM_COMMON_H_
#define BOTAN_DILITHIUM_COMMON_H_

#include <botan/module_lattice_keys.h>
#include <botan/pk_keys.h>

namespace Botan {

class BOTAN_PUBLIC_API(3, 0) DilithiumMode final {
   public:
      enum Mode : uint8_t /* NOLINT(*-use-enum-class) */ {
         Dilithium4x4 BOTAN_DEPRECATED("Dilithium R3 is deprecated - use ML-DSA") = 1,
         Dilithium4x4_AES BOTAN_DEPRECATED("Dilithium AES mode is deprecated"),
         Dilithium6x5 BOTAN_DEPRECATED("Dilithium R3 is deprecated - use ML-DSA"),
         Dilithium6x5_AES BOTAN_DEPRECATED("Dilithium AES mode is deprecated"),
         Dilithium8x7 BOTAN_DEPRECATED("Dilithium R3 is deprecated - use ML-DSA"),
         Dilithium8x7_AES BOTAN_DEPRECATED("Dilithium AES mode is deprecated"),
         ML_DSA_4x4,
         ML_DSA_6x5,
         ML_DSA_8x7,
      };

   public:
      // NOLINTNEXTLINE(*-explicit-conversions)
      DilithiumMode(Mode mode) : m_mode(mode) {}

      explicit DilithiumMode(const OID& oid);
      explicit DilithiumMode(std::string_view str);

      OID object_identifier() const;
      std::string to_string() const;

      BOTAN_DEPRECATED("Dilithium AES mode is deprecated") bool is_aes() const;
      BOTAN_DEPRECATED("Dilithium AES mode is deprecated") bool is_modern() const;
      bool is_ml_dsa() const;

      bool is_dilithium_round3() const { return !is_ml_dsa(); }

      bool is_available() const;

      Mode mode() const { return m_mode; }

   private:
      Mode m_mode;
};

class Dilithium_PublicKeyInternal;
class Dilithium_PrivateKeyInternal;

/**
 * This implementation is based on
 * https://github.com/pq-crystals/dilithium/commit/3e9b9f1412f6c7435dbeb4e10692ea58f181ee51
 *
 * Note that this is _not_ compatible with the round 3 submission of the NIST competition.
 */
class BOTAN_PUBLIC_API(3, 0) Dilithium_PublicKey : public virtual Public_Key {
   public:
      std::string algo_name() const override;

      AlgorithmIdentifier algorithm_identifier() const override;

      OID object_identifier() const override;

      size_t key_length() const override;

      size_t estimated_strength() const override;

      std::vector<uint8_t> raw_public_key_bits() const override;

      std::vector<uint8_t> public_key_bits() const override;

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

      bool supports_operation(PublicKeyOperation op) const override { return (op == PublicKeyOperation::Signature); }

      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator& rng) const final;

      Dilithium_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> pk);

      Dilithium_PublicKey(std::span<const uint8_t> pk, DilithiumMode mode);

      std::unique_ptr<PK_Ops::Verification> _create_verification_op(const PK_Signature_Options& options) const override;

      std::unique_ptr<PK_Ops::Verification> create_x509_verification_op(const AlgorithmIdentifier& signature_algorithm,
                                                                        std::string_view provider) const override;

   protected:
      Dilithium_PublicKey() = default;

      friend class Dilithium_Verification_Operation;
      friend class Dilithium_Signature_Operation;

      std::shared_ptr<const Dilithium_PublicKeyInternal> m_public;  // NOLINT(*non-private-member-variable*)
};

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

class BOTAN_PUBLIC_API(3, 0) Dilithium_PrivateKey final : public virtual Dilithium_PublicKey,
                                                          public virtual Module_Lattice_PrivateKey,
                                                          public virtual Private_Key {
   public:
      std::unique_ptr<Public_Key> public_key() const override;

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

      /**
       * Generates a new key pair.
       *
       * New ML-DSA keys are encoded in the format MlPrivateKeyFormat::Both,
       * new Dilithium round 3 keys in MlPrivateKeyFormat::Expanded.
       */
      Dilithium_PrivateKey(RandomNumberGenerator& rng, DilithiumMode mode);

      /**
       * Read an encoded private key.
       *
       * ML-DSA keys are accepted in all three CHOICE alternatives of RFC 9881
       * (seed, expanded key, or both) and, for backwards compatibility, as the
       * raw 32-byte seed or the raw expanded key of FIPS 204. Dilithium round 3
       * keys are accepted as the raw expanded key only. The detected format is
       * retained, see private_key_format().
       */
      Dilithium_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> sk);

      /**
       * Read an encoded private key given the dilithium @p mode. See the
       * constructor above for the accepted encodings.
       */
      Dilithium_PrivateKey(std::span<const uint8_t> sk, DilithiumMode mode);

      /**
       * The format this key was loaded from, or the default format of a newly
       * generated key (MlPrivateKeyFormat::Both for ML-DSA). It is the format
       * used for private_key_bits(), private_key_info() and
       * raw_private_key_bits().
       */
      MlPrivateKeyFormat private_key_format() const override;

      /**
       * The raw key material in the given @p format: the 32-byte seed or the
       * expanded key of FIPS 204, without ASN.1 wrapping.
       *
       * @throws Encoding_Error for MlPrivateKeyFormat::Both (no raw encoding
       *         exists), for MlPrivateKeyFormat::Seed if the key was loaded
       *         from an expanded key (and thus holds no seed), and for
       *         anything but MlPrivateKeyFormat::Expanded on Dilithium round 3 keys.
       */
      secure_vector<uint8_t> formatted_raw_private_key_bits(MlPrivateKeyFormat format) const override;

      /**
       * The ML-DSA-PrivateKey CHOICE encoding of RFC 9881 in the given
       * @p format, i.e. the content of the PKCS#8 privateKey field. Dilithium
       * round 3 keys are encoded as the raw expanded key
       * (MlPrivateKeyFormat::Expanded only).
       *
       * @throws Encoding_Error if the key cannot be encoded in @p format
       *         (see formatted_raw_private_key_bits())
       */
      secure_vector<uint8_t> formatted_private_key_bits(MlPrivateKeyFormat format) const override;

      /**
       * The seed for keys in the formats MlPrivateKeyFormat::Seed and
       * MlPrivateKeyFormat::Both, the expanded key of FIPS 204 for keys in the
       * format MlPrivateKeyFormat::Expanded.
       */
      secure_vector<uint8_t> raw_private_key_bits() const override;

      std::unique_ptr<PK_Ops::Signature> _create_signature_op(RandomNumberGenerator& rng,
                                                              const PK_Signature_Options& options) const override;

      bool is_mldsa() const;

      bool is_dilithium_round3() const;

   private:
      friend class Dilithium_Signature_Operation;

      std::shared_ptr<const Dilithium_PrivateKeyInternal> m_private;
      MlPrivateKeyFormat m_private_key_format;
};

BOTAN_DIAGNOSTIC_POP

}  // namespace Botan

#endif
