/*
* ECIES
* (C) 2016 Philipp Weber
*     2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ECIES_H_
#define BOTAN_ECIES_H_

#include <botan/cipher_mode.h>
#include <botan/ec_apoint.h>
#include <botan/ec_group.h>
#include <botan/mac.h>
#include <botan/pubkey.h>
#include <botan/secmem.h>
#include <botan/symkey.h>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
   #include <botan/ec_point.h>
#endif

namespace Botan {

class RandomNumberGenerator;

/**
* Flags controlling ECIES operation
*
* Two of the flags are related to how cofactors are handled.
* Support for cofactors is deprecated and will be removed in Botan4.
*
* The CheckMode flag is completely ignored; we always check that the point is
* valid.
*
* TODO(Botan4) remove this enum
*/
enum class ECIES_Flags : uint32_t {
   None = 0,
   /// if set: prefix the input of the (ecdh) key agreement with the encoded (ephemeral) public key
   SingleHashMode = 1,
   /// (decryption only) if set: use cofactor multiplication during (ecdh) key agreement
   /// This only matters if the curve has a cofactor
   CofactorMode = 2,
   /// if set: use ecdhc instead of ecdh.
   /// This only matters if the curve has a cofactor
   OldCofactorMode = 4,
   /// (decryption only) if set: test if the (ephemeral) public key is on the curve
   /// Note that we actually ignore this flag and always check the key
   CheckMode = 8,

   NONE BOTAN_DEPRECATED("Use None") = None,
   SINGLE_HASH_MODE BOTAN_DEPRECATED("Use SingleHashMode") = SingleHashMode,
   COFACTOR_MODE BOTAN_DEPRECATED("Use CofactorMode") = CofactorMode,
   OLD_COFACTOR_MODE BOTAN_DEPRECATED("Use OldCofactorMode") = OldCofactorMode,
   CHECK_MODE BOTAN_DEPRECATED("Use CheckMode") = CheckMode,
};

inline ECIES_Flags operator|(ECIES_Flags a, ECIES_Flags b) {
   // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
   return static_cast<ECIES_Flags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline ECIES_Flags operator&(ECIES_Flags a, ECIES_Flags b) {
   return static_cast<ECIES_Flags>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

/**
* Parameters for ECIES secret derivation
*/
class BOTAN_PUBLIC_API(2, 0) ECIES_KA_Params {
   public:
      /**
      * @param group ec domain parameters of the involved ec keys
      * @param kdf_spec name of the key derivation function
      * @param length length of the secret to be derived
      * @param point_format format of encoded keys (affects the secret derivation if single_hash_mode is used)
      * @param single_hash_mode prefix the KDF input with the ephemeral public key (recommended)
      */
      ECIES_KA_Params(const EC_Group& group,
                      std::string_view kdf_spec,
                      size_t length,
                      EC_Point_Format point_format = EC_Point_Format::Uncompressed,
                      bool single_hash_mode = true);

      /**
      * @param group ec domain parameters of the involved ec keys
      * @param kdf_spec name of the key derivation function
      * @param length length of the secret to be derived
      * @param point_format format of encoded keys (affects the secret derivation if single_hash_mode is used)
      * @param flags options, see documentation of ECIES_Flags
      *
      * This constructor makes sense only if you are using the CofactorMode or
      * OldCofactorMode flags. Support for cofactors in EC_Group is deprecated
      * and will be removed in Botan4.
      *
      * TODO(Botan4) remove this constructor when cofactor support is removed
      */
      BOTAN_DEPRECATED("Prefer other constructor, see header comment")
      ECIES_KA_Params(const EC_Group& group,
                      std::string_view kdf_spec,
                      size_t length,
                      EC_Point_Format point_format,
                      ECIES_Flags flags);

      ECIES_KA_Params(const ECIES_KA_Params&) = default;
      ECIES_KA_Params& operator=(const ECIES_KA_Params&) = delete;

      virtual ~ECIES_KA_Params() = default;

      const EC_Group& group() const { return m_group; }

      size_t secret_length() const { return m_length; }

      bool single_hash_mode() const { return m_single_hash_mode; }

      // TODO(Botan4) remove this when cofactor support is removed
      bool cofactor_mode() const { return m_cofactor_mode; }

      // TODO(Botan4) remove this when cofactor support is removed
      bool old_cofactor_mode() const { return m_old_cofactor_mode; }

      // TODO(Botan4) remove this when cofactor support is removed
      bool check_mode() const { return m_check_mode; }

      EC_Point_Format point_format() const { return m_point_format; }

      const std::string& kdf() const { return m_kdf; }

      BOTAN_DEPRECATED("Use kdf") const std::string& kdf_spec() const { return kdf(); }

      BOTAN_DEPRECATED("Use group") const EC_Group& domain() const { return group(); }

      BOTAN_DEPRECATED("Use point_format") EC_Point_Format compression_type() const { return point_format(); }

   private:
      const EC_Group m_group;
      const std::string m_kdf;
      const size_t m_length;
      const EC_Point_Format m_point_format;
      const bool m_single_hash_mode;
      const bool m_check_mode;         // TODO(Botan4) remove this field
      const bool m_cofactor_mode;      // TODO(Botan4) remove this field
      const bool m_old_cofactor_mode;  // TODO(Botan4) remove this field
};

class BOTAN_PUBLIC_API(2, 0) ECIES_System_Params final : public ECIES_KA_Params {
   public:
      /**
      * @param group ec domain parameters of the involved ec keys
      * @param kdf_spec name of the key derivation function
      * @param dem_algo_spec name of the data encryption method
      * @param dem_key_len length of the key used for the data encryption method
      * @param mac_spec name of the message authentication code
      * @param mac_key_len length of the key used for the message authentication code
      */
      ECIES_System_Params(const EC_Group& group,
                          std::string_view kdf_spec,
                          std::string_view dem_algo_spec,
                          size_t dem_key_len,
                          std::string_view mac_spec,
                          size_t mac_key_len,
                          EC_Point_Format point_format = EC_Point_Format::Uncompressed,
                          bool single_hash_mode = false);

      /**
      * @param group ec domain parameters of the involved ec keys
      * @param kdf_spec name of the key derivation function
      * @param dem_algo_spec name of the data encryption method
      * @param dem_key_len length of the key used for the data encryption method
      * @param mac_spec name of the message authentication code
      * @param mac_key_len length of the key used for the message authentication code
      * @param point_format format of encoded keys (affects the secret derivation if single_hash_mode is used)
      * @param flags options, see documentation of ECIES_Flags
      *
      * This constructor makes sense only if you are using the CofactorMode or
      * OldCofactorMode flags. Support for cofactors in EC_Group is deprecated
      * and will be removed in Botan4.
      *
      * TODO(Botan4) remove this constructor when cofactor support is removed
      */
      BOTAN_DEPRECATED("Prefer other constructor, see header comment")
      ECIES_System_Params(const EC_Group& group,
                          std::string_view kdf_spec,
                          std::string_view dem_algo_spec,
                          size_t dem_key_len,
                          std::string_view mac_spec,
                          size_t mac_key_len,
                          EC_Point_Format point_format,
                          ECIES_Flags flags);

      ECIES_System_Params(const ECIES_System_Params&) = default;
      ECIES_System_Params& operator=(const ECIES_System_Params&) = delete;
      ~ECIES_System_Params() override = default;

      /// creates an instance of the message authentication code
      std::unique_ptr<MessageAuthenticationCode> create_mac() const;

      /// creates an instance of the data encryption method
      std::unique_ptr<Cipher_Mode> create_cipher(Cipher_Dir direction) const;

      /// returns the length of the key used by the data encryption method
      size_t dem_keylen() const { return m_dem_keylen; }

      /// returns the length of the key used by the message authentication code
      size_t mac_keylen() const { return m_mac_keylen; }

   private:
      const std::string m_dem_spec;
      const size_t m_dem_keylen;
      const std::string m_mac_spec;
      const size_t m_mac_keylen;
};

/**
* ECIES secret derivation according to ISO 18033-2
*/
class BOTAN_PUBLIC_API(2, 0) ECIES_KA_Operation {
   public:
      /**
      * @param private_key the (ephemeral) private key which is used to derive the secret
      * @param ecies_params settings for ecies
      * @param for_encryption disable cofactor mode if the secret will be used for encryption
      * (according to ISO 18033 cofactor mode is only used during decryption)
      * @param rng the RNG to use
      */
      ECIES_KA_Operation(const PK_Key_Agreement_Key& private_key,
                         const ECIES_KA_Params& ecies_params,
                         bool for_encryption,
                         RandomNumberGenerator& rng);

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
      /**
      * Performs a key agreement with the provided keys and derives the secret from the result
      * @param eph_public_key_bin the encoded (ephemeral) public key which belongs to the used (ephemeral) private key
      * @param other_public_key_point public key point of the other party
      */
      SymmetricKey derive_secret(const std::vector<uint8_t>& eph_public_key_bin,
                                 const EC_Point& other_public_key_point) const;
#endif

      /**
      * Performs a key agreement with the provided keys and derives the secret from the result
      * @param eph_public_key_bin the encoded (ephemeral) public key which belongs to the used (ephemeral) private key
      * @param other_public_key_point public key point of the other party
      */
      SymmetricKey derive_secret(std::span<const uint8_t> eph_public_key_bin,
                                 const EC_AffinePoint& other_public_key_point) const;

   private:
      const PK_Key_Agreement m_ka;
      const ECIES_KA_Params m_params;
};

/**
* ECIES Encryption according to ISO 18033-2
*/
class BOTAN_PUBLIC_API(2, 0) ECIES_Encryptor final : public PK_Encryptor {
   public:
      /**
      * @param private_key the (ephemeral) private key which is used for the key agreement
      * @param ecies_params settings for ecies
      * @param rng random generator to use
      */
      ECIES_Encryptor(const PK_Key_Agreement_Key& private_key,
                      const ECIES_System_Params& ecies_params,
                      RandomNumberGenerator& rng);

      /**
      * Creates an ephemeral private key which is used for the key agreement
      * @param rng random generator used during private key generation
      * @param ecies_params settings for ecies
      */
      ECIES_Encryptor(RandomNumberGenerator& rng, const ECIES_System_Params& ecies_params);

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
      /// Set the public key of the other party
      void set_other_key(const EC_Point& public_point) {
         m_other_point = EC_AffinePoint(m_params.group(), public_point);
      }
#endif

      /// Set the public key of the other party
      void set_other_key(const EC_AffinePoint& pt) { m_other_point = pt; }

      /// Set the initialization vector for the data encryption method
      void set_initialization_vector(const InitializationVector& iv) { m_iv = iv; }

      /// Set the label which is appended to the input for the message authentication code
      void set_label(std::string_view label) { m_label.assign(label.begin(), label.end()); }

   private:
      std::vector<uint8_t> enc(const uint8_t data[], size_t length, RandomNumberGenerator&) const override;

      size_t maximum_input_size() const override;

      size_t ciphertext_length(size_t ptext_len) const override;

      const ECIES_KA_Operation m_ka;
      const ECIES_System_Params m_params;
      std::unique_ptr<MessageAuthenticationCode> m_mac;
      std::unique_ptr<Cipher_Mode> m_cipher;
      std::vector<uint8_t> m_eph_public_key_bin;
      InitializationVector m_iv;
      std::optional<EC_AffinePoint> m_other_point;
      std::vector<uint8_t> m_label;
};

/**
* ECIES Decryption according to ISO 18033-2
*/
class BOTAN_PUBLIC_API(2, 0) ECIES_Decryptor final : public PK_Decryptor {
   public:
      /**
      * @param private_key the private key which is used for the key agreement
      * @param ecies_params settings for ecies
      * @param rng the random generator to use
      */
      ECIES_Decryptor(const PK_Key_Agreement_Key& private_key,
                      const ECIES_System_Params& ecies_params,
                      RandomNumberGenerator& rng);

      /// Set the initialization vector for the data encryption method
      void set_initialization_vector(const InitializationVector& iv) { m_iv = iv; }

      /// Set the label which is appended to the input for the message authentication code
      void set_label(std::string_view label) { m_label = std::vector<uint8_t>(label.begin(), label.end()); }

   private:
      secure_vector<uint8_t> do_decrypt(uint8_t& valid_mask, const uint8_t in[], size_t in_len) const override;

      size_t plaintext_length(size_t ctext_len) const override;

      const ECIES_KA_Operation m_ka;
      const ECIES_System_Params m_params;
      std::unique_ptr<MessageAuthenticationCode> m_mac;
      std::unique_ptr<Cipher_Mode> m_cipher;
      InitializationVector m_iv;
      std::vector<uint8_t> m_label;
};

}  // namespace Botan

#endif
