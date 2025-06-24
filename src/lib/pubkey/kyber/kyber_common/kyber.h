/*
 * Crystals Kyber key encapsulation mechanism
 * Based on the public domain reference implementation by the
 * designers (https://github.com/pq-crystals/kyber)
 *
 * Further changes
 * (C) 2021-2022 Jack Lloyd
 * (C) 2021-2022 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
 * (C) 2021-2022 René Meusel and Hannes Rantzsch, neXenio GmbH
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_KYBER_COMMON_H_
#define BOTAN_KYBER_COMMON_H_

#include <botan/exceptn.h>
#include <botan/pk_keys.h>

#include <span>

#if !defined(BOTAN_HAS_KYBER_90S) && !defined(BOTAN_HAS_KYBER) && !defined(BOTAN_HAS_ML_KEM)
static_assert(
   false,
   "botan module 'kyber_common' is useful only when enabling at least one of those modules: 'kyber', 'kyber_90s', 'ml_kem'");
#endif

namespace Botan {

class BOTAN_PUBLIC_API(3, 0) KyberMode {
   public:
      enum Mode : uint8_t {
         // Kyber512 as proposed in round 3 of the NIST competition
         Kyber512_R3 = 0,
         // Kyber768 as proposed in round 3 of the NIST competition
         Kyber768_R3 = 1,
         // Kyber1024 as proposed in round 3 of the NIST competition
         Kyber1024_R3 = 2,

         Kyber512 BOTAN_DEPRECATED("Use Kyber512_R3") = Kyber512_R3,
         Kyber768 BOTAN_DEPRECATED("Use Kyber768_R3") = Kyber768_R3,
         Kyber1024 BOTAN_DEPRECATED("Use Kyber1024_R3") = Kyber1024_R3,

         ML_KEM_512 = 3,
         ML_KEM_768 = 4,
         ML_KEM_1024 = 5,

         Kyber512_90s BOTAN_DEPRECATED("Kyber 90s mode is deprecated") = 6,
         Kyber768_90s BOTAN_DEPRECATED("Kyber 90s mode is deprecated") = 7,
         Kyber1024_90s BOTAN_DEPRECATED("Kyber 90s mode is deprecated") = 8,
      };

      // NOLINTNEXTLINE(*-explicit-conversions)
      KyberMode(Mode mode);

      explicit KyberMode(const OID& oid);
      explicit KyberMode(std::string_view str);

      OID object_identifier() const;
      std::string to_string() const;

      Mode mode() const { return m_mode; }

      BOTAN_DEPRECATED("Kyber 90s mode is deprecated") bool is_90s() const;

      BOTAN_DEPRECATED("Kyber 90s mode is deprecated") bool is_modern() const;

      bool is_ml_kem() const;

      bool is_kyber_round3() const;

      bool is_available() const;

      bool operator==(const KyberMode& other) const { return m_mode == other.m_mode; }

      bool operator!=(const KyberMode& other) const { return !(*this == other); }

   private:
      Mode m_mode;
};

/// Byte encoding format of ML-KEM and ML-DSA the private key
enum class MlPrivateKeyFormat : uint8_t {
   /// Only supported for ML-KEM/ML-DSA keys:
   /// - ML-KEM: 64-byte seed: d || z
   /// - ML-DSA: 32-byte seed: xi (private_key_bits_with_format not yet
   ///   yet supported for ML-DSA)
   Seed,
   /// The expanded format, i.e., the format specified in FIPS-203/204.
   Expanded,
};

class Kyber_PublicKeyInternal;
class Kyber_PrivateKeyInternal;

class BOTAN_PUBLIC_API(3, 0) Kyber_PublicKey : public virtual Public_Key {
   public:
      Kyber_PublicKey(std::span<const uint8_t> pub_key, KyberMode mode);

      Kyber_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits);

      Kyber_PublicKey(const Kyber_PublicKey& other);
      Kyber_PublicKey& operator=(const Kyber_PublicKey& other) = default;
      Kyber_PublicKey(Kyber_PublicKey&& other) = default;
      Kyber_PublicKey& operator=(Kyber_PublicKey&& other) = default;

      ~Kyber_PublicKey() override = default;

      std::string algo_name() const override;

      AlgorithmIdentifier algorithm_identifier() const override;

      OID object_identifier() const override;

      size_t key_length() const override;

      size_t estimated_strength() const override;

      std::vector<uint8_t> raw_public_key_bits() const override;

      std::vector<uint8_t> public_key_bits() const override;

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator& rng) const final;

      bool supports_operation(PublicKeyOperation op) const override {
         return (op == PublicKeyOperation::KeyEncapsulation);
      }

      std::unique_ptr<PK_Ops::KEM_Encryption> create_kem_encryption_op(std::string_view params,
                                                                       std::string_view provider) const override;

      KyberMode mode() const;

   protected:
      Kyber_PublicKey() = default;

      static std::shared_ptr<Kyber_PublicKeyInternal> initialize_from_encoding(std::span<const uint8_t> pub_key,
                                                                               KyberMode m);

   protected:
      friend class Kyber_KEM_Encryptor;
      friend class Kyber_KEM_Decryptor;

      std::shared_ptr<Kyber_PublicKeyInternal> m_public;  // NOLINT(*non-private-member-variable*)
};

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

class BOTAN_PUBLIC_API(3, 0) Kyber_PrivateKey final : public virtual Kyber_PublicKey,
                                                      public virtual Private_Key {
   public:
      /**
       * Create a new private key. The private key will be encoded as the 64 byte
       * seed.
       */
      Kyber_PrivateKey(RandomNumberGenerator& rng, KyberMode mode);

      /**
       * Import a private key using its key bytes. Supported are key bytes as
       * 64-byte seeds (not supported for Kyber Round 3 instances),
       * as well as the expanded encoding specified by FIPS 203. Note that the
       * encoding used in this constructor is reflected by the calls for
       * private_key_bits, private_key_info, etc.
       */
      Kyber_PrivateKey(std::span<const uint8_t> sk, KyberMode mode);

      /**
       * Import a private key using its key bytes. Supported are key bytes as
       * 64-byte seeds (not supported for Kyber Round 3 instances),
       * as well as the expanded encoding specified by FIPS 203. Note that the
       * encoding used in this constructor is reflected by the calls for
       * private_key_bits, private_key_info, etc.
       */
      Kyber_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits);

      std::unique_ptr<Public_Key> public_key() const override;

      secure_vector<uint8_t> private_key_bits() const override;

      secure_vector<uint8_t> raw_private_key_bits() const override;

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

      std::unique_ptr<PK_Ops::KEM_Decryption> create_kem_decryption_op(RandomNumberGenerator& rng,
                                                                       std::string_view params,
                                                                       std::string_view provider) const override;

      /**
       * The private key format from which the key was loaded. It is the format
       * used for the private_key_bits(), raw_private_key_bits() andFIPS
       * private_key_info() methods.
       *
       * Note that keys in Seed format can be serialized to Expanded format
       * using the method private_key_bits_with_format but NOT the other way
       * around.
       */
      MlPrivateKeyFormat private_key_format() const;

      /**
       * Encode the private key in the specified format. Note that the seed
       * format is only available for new ML-KEM keys and those loaded from
       * seeds.
       * @throws Encoding_Error if the private key cannot be encoded in the
       *         requested format.
       */
      secure_vector<uint8_t> private_key_bits_with_format(MlPrivateKeyFormat format) const;

   private:
      friend class Kyber_KEM_Decryptor;

      std::shared_ptr<Kyber_PrivateKeyInternal> m_private;
};

BOTAN_DIAGNOSTIC_POP

}  // namespace Botan

#endif
