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

#include <botan/module_lattice_keys.h>
#include <botan/pk_keys.h>
#include <span>

#if !defined(BOTAN_HAS_KYBER_90S) && !defined(BOTAN_HAS_KYBER) && !defined(BOTAN_HAS_ML_KEM)
static_assert(
   false,
   "botan module 'kyber_common' is useful only when enabling at least one of those modules: 'kyber', 'kyber_90s', 'ml_kem'");
#endif

namespace Botan {

class BOTAN_PUBLIC_API(3, 0) KyberMode final {
   public:
      enum Mode : uint8_t /* NOLINT(*-use-enum-class) */ {
         // Kyber512 as proposed in round 3 of the NIST competition
         Kyber512_R3 BOTAN_DEPRECATED("Kyber R3 is deprecated - use ML-KEM") = 0,
         // Kyber768 as proposed in round 3 of the NIST competition
         Kyber768_R3 BOTAN_DEPRECATED("Kyber R3 is deprecated - use ML-KEM") = 1,
         // Kyber1024 as proposed in round 3 of the NIST competition
         Kyber1024_R3 BOTAN_DEPRECATED("Kyber R3 is deprecated - use ML-KEM") = 2,

         Kyber512 BOTAN_DEPRECATED("Kyber R3 is deprecated - use ML-KEM") = 0,
         Kyber768 BOTAN_DEPRECATED("Kyber R3 is deprecated - use ML-KEM") = 1,
         Kyber1024 BOTAN_DEPRECATED("Kyber R3 is deprecated - use ML-KEM") = 2,

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

      std::unique_ptr<PK_Ops::KEM_Encryption> _create_kem_encryption_op(
         const PK_KEM_Options_Reader& options) const override;

      KyberMode mode() const;

   protected:
      Kyber_PublicKey() = default;

      static std::shared_ptr<Kyber_PublicKeyInternal> initialize_from_encoding(std::span<const uint8_t> pub_key,
                                                                               KyberMode m);

   protected:
      friend class Kyber_KEM_Encryptor;
      friend class Kyber_KEM_Decryptor;

      std::shared_ptr<const Kyber_PublicKeyInternal> m_public;  // NOLINT(*non-private-member-variable*)
};

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

class BOTAN_PUBLIC_API(3, 0) Kyber_PrivateKey final : public virtual Kyber_PublicKey,
                                                      public virtual Module_Lattice_PrivateKey,
                                                      public virtual Private_Key {
   public:
      /**
       * Create a new private key.
       *
       * New ML-KEM keys are encoded in the format MlPrivateKeyFormat::Both,
       * new Kyber round 3 keys in MlPrivateKeyFormat::Expanded.
       */
      Kyber_PrivateKey(RandomNumberGenerator& rng, KyberMode mode);

      /**
       * Import a private key using its key bytes.
       *
       * ML-KEM keys are accepted in all three CHOICE alternatives of RFC 9935
       * (seed, expanded key, or both) and, for backwards compatibility, as the
       * raw 64-byte seed d || z or the raw expanded key of FIPS 203. Kyber
       * round 3 keys are accepted as the raw expanded key only. The detected
       * format is retained, see private_key_format().
       */
      Kyber_PrivateKey(std::span<const uint8_t> sk, KyberMode mode);

      /**
       * Import a private key using its key bytes. See the constructor above
       * for the accepted encodings.
       */
      Kyber_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits);

      std::unique_ptr<Public_Key> public_key() const override;

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

      std::unique_ptr<PK_Ops::KEM_Decryption> _create_kem_decryption_op(
         RandomNumberGenerator& rng, const PK_KEM_Options_Reader& options) const override;

      /**
       * The format this key was loaded from, or the default format of a newly
       * generated key (MlPrivateKeyFormat::Both for ML-KEM). It is the format
       * used for private_key_bits(), private_key_info() and
       * raw_private_key_bits().
       *
       * Note that keys that contain the seed can be serialized in any format
       * using the formatted_*() methods, whereas keys loaded from an expanded
       * key can NOT be serialized as seed.
       */
      MlPrivateKeyFormat private_key_format() const override;

      /**
       * The raw key material in the given @p format: the 64-byte seed d || z
       * or the expanded key of FIPS 203, without ASN.1 wrapping.
       *
       * @throws Encoding_Error for MlPrivateKeyFormat::Both (no raw encoding
       *         exists), for MlPrivateKeyFormat::Seed if the key was loaded
       *         from an expanded key (and thus holds no seed), and for
       *         anything but MlPrivateKeyFormat::Expanded on Kyber round 3 keys.
       */
      secure_vector<uint8_t> formatted_raw_private_key_bits(MlPrivateKeyFormat format) const override;

      /**
       * The ML-KEM-PrivateKey CHOICE encoding of RFC 9935 in the given
       * @p format, i.e. the content of the PKCS#8 privateKey field. Kyber
       * round 3 keys are encoded as the raw expanded key
       * (MlPrivateKeyFormat::Expanded only).
       *
       * @throws Encoding_Error if the key cannot be encoded in @p format
       *         (see formatted_raw_private_key_bits())
       */
      secure_vector<uint8_t> formatted_private_key_bits(MlPrivateKeyFormat format) const override;

      /**
       * The seed for keys in the formats MlPrivateKeyFormat::Seed and
       * MlPrivateKeyFormat::Both, the expanded key of FIPS 203 for keys in the
       * format MlPrivateKeyFormat::Expanded.
       */
      secure_vector<uint8_t> raw_private_key_bits() const override;

      BOTAN_DEPRECATED("Use formatted_raw_private_key_bits")
      secure_vector<uint8_t> private_key_bits_with_format(MlPrivateKeyFormat format) const {
         return formatted_raw_private_key_bits(format);
      }

   private:
      friend class Kyber_KEM_Decryptor;

      std::shared_ptr<const Kyber_PrivateKeyInternal> m_private;
      MlPrivateKeyFormat m_private_key_format;
};

BOTAN_DIAGNOSTIC_POP

}  // namespace Botan

#endif
