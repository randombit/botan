/**
* Ounsworth KEM Combiner Mode
*
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_OUNSWORTH_MODE_H_
#define BOTAN_OUNSWORTH_MODE_H_

#include <botan/hash.h>
#include <botan/hybrid_kem.h>
#include <botan/kdf.h>
#include <botan/mac.h>
#include <botan/pk_algs.h>

#include <functional>
#include <variant>

namespace Botan::Ounsworth {

/**
 * @brief The KDF options for the Ounsworth KEM combiner
 * (see Ounsworth draft section 5)
 */
enum Kdf_Type { KMAC128, KMAC256, SHA3_256, SHA3_512 };

/**
 * @brief Predefined sub-algorithm types
 *
 * Note that additional custom algorithms can be used by calling the
 * SubAlgo constructor with the appropriate callbacks.
 */
enum class BOTAN_UNSTABLE_API Sub_Algo_Type {
#ifdef BOTAN_HAS_KYBER
   Kyber512_R3,
   Kyber768_R3,
   Kyber1024_R3,
#endif
#ifdef BOTAN_HAS_FRODOKEM_SHAKE
   FrodoKEM640_SHAKE,
   FrodoKEM976_SHAKE,
   FrodoKEM1344_SHAKE,
#endif
#ifdef BOTAN_HAS_FRODOKEM_AES
   FrodoKEM640_AES,
   FrodoKEM976_AES,
   FrodoKEM1344_AES,
#endif
#ifdef BOTAN_HAS_X25519
   X25519,
#endif
#ifdef BOTAN_HAS_X448
   X448,
#endif
#ifdef BOTAN_HAS_ECDH
   ECDH_Secp192R1,
   ECDH_Secp224R1,
   ECDH_Secp256R1,
   ECDH_Secp384R1,
   ECDH_Secp521R1,
   ECDH_Brainpool256R1,
   ECDH_Brainpool384R1,
   ECDH_Brainpool512R1,
#endif
};

/**
 * @brief Defines a sub-algorithm that is part of the Ounsworth KEM combiner.
 *
 * The easiest method is to use the predefined Sub_Algo_Type values for
 * instantiation. Custom algorithms can be used by providing the appropriate
 * callbacks and size information.
 */
class BOTAN_UNSTABLE_API Sub_Algo {
   public:
      /**
       * @brief Define a sub-algorithm by a predefined type.
       *
       * The callbacks and sizes are automatically set based on the type.
       *
       * @param algo the predefined sub-algorithm type
       */
      Sub_Algo(Sub_Algo_Type algo);

      /**
       * @brief Define a custom sub-algorithm that may not be part of the
       * predefined types.
       *
       * @param create_private_key_callback A callback for secret key creation
       * @param load_private_key_callback A callback for loading a secret key using the output of raw_private_key_bits()
       * @param load_public_key_callback A callback for loading a public key using the output of raw_public_key_bits()
       * @param raw_sk_length The length of raw_private_key_bits() in bytes
       * @param raw_pk_length The length of raw_public_key_bits() in bytes
       */
      Sub_Algo(std::function<std::unique_ptr<Private_Key>(RandomNumberGenerator&)> create_private_key_callback,
               std::function<std::unique_ptr<Private_Key>(std::span<const uint8_t>)> load_private_key_callback,
               std::function<std::unique_ptr<Public_Key>(std::span<const uint8_t>)> load_public_key_callback,
               size_t raw_sk_length,
               size_t raw_pk_length) :
            m_create_private_key_callback(std::move(create_private_key_callback)),
            m_load_private_key_callback(std::move(load_private_key_callback)),
            m_load_public_key_callback(std::move(load_public_key_callback)),
            m_raw_sk_length(raw_sk_length),
            m_raw_pk_length(raw_pk_length),
            m_maybe_type(std::nullopt) {}

      std::unique_ptr<Private_Key> create_private_key(RandomNumberGenerator& rng) const {
         return m_create_private_key_callback(rng);
      }

      std::unique_ptr<Private_Key> load_private_key(std::span<const uint8_t> key_data) const {
         return m_load_private_key_callback(key_data);
      }

      std::unique_ptr<Public_Key> load_public_key(std::span<const uint8_t> key_data) const {
         return m_load_public_key_callback(key_data);
      }

      size_t raw_pk_length() const { return m_raw_pk_length; }

      size_t raw_sk_length() const { return m_raw_sk_length; }

      /// Get the type of the sub-algorithm, if the constructor was called with a predefined type
      std::optional<Sub_Algo_Type> type() const { return m_maybe_type; }

   private:
      std::function<std::unique_ptr<Private_Key>(RandomNumberGenerator&)> m_create_private_key_callback;
      std::function<std::unique_ptr<Private_Key>(std::span<const uint8_t>)> m_load_private_key_callback;
      std::function<std::unique_ptr<Public_Key>(std::span<const uint8_t>)> m_load_public_key_callback;
      size_t m_raw_sk_length;
      size_t m_raw_pk_length;
      std::optional<Sub_Algo_Type> m_maybe_type;
};

/**
 * @brief Defines the used mode of the Ounsworth KEM combiner.
 *
 * The mode defines the sub-algorithms and the KDF to use.
 */
class BOTAN_UNSTABLE_API Mode {
   public:
      /**
       * @brief Define the Ounsworth KEM combiner mode by a set of sub-algorithms
       * and a KDF.
       *
       * @param sub_algos The sub-algorithms to use. List size must be greater than two.
       * @param kdf The KDF to use
       */
      Mode(std::vector<Sub_Algo> sub_algos, Kdf_Type kdf) : m_sub_algos(std::move(sub_algos)), m_kdf(kdf) {
         BOTAN_ARG_CHECK(m_sub_algos.size() >= 2, "At least two sub-algorithms must be provided");
      }

      /**
       * @brief Construct an Ounsworth KEM combiner mode from an AlgorithmIdentifier
       *
       * @param alg_id the algorithm identifier
       */
      Mode(const AlgorithmIdentifier& alg_id);

      /**
       * @brief Construct an Ounsworth KEM combiner mode from a formatted string
       *
       * Format: OunsworthKEMCombiner/[sub-algo]/.../[sub-algo]/[kdf]
       * For example: "OunsworthKEMCombiner/Kyber-512-r3/X25519/KMAC-128"
       *
       * [sub-algo] is one of:
       *   Kyber-512-r3, Kyber-768-r3, Kyber-1024-r3, FrodoKEM-640-SHAKE,
       *   FrodoKEM-976-SHAKE, FrodoKEM-1344-SHAKE, FrodoKEM-640-AES,
       *   FrodoKEM-976-AES, FrodoKEM-1344-AES, X25519, X448, ECDH-secp192r1,
       *   ECDH-secp224r1, ECDH-secp256r1, ECDH-secp384r1, ECDH-secp521r1,
       *   ECDH-brainpool256r1, ECDH-brainpool384r1, ECDH-brainpool512r1
       *
       * [kdf] is one of:
       *   KMAC-128, KMAC-256, SHA3-256, SHA3-512
       *
       * @param mode_str formatted string of the mode
       */
      Mode(std::string_view mode_str);

      const std::vector<Sub_Algo>& sub_algos() const { return m_sub_algos; }

      Kdf_Type kdf_mode() const { return m_kdf; }

      std::unique_ptr<KDF> kdf_instance() const;

      bool is_mac_based_kdf() const { return kdf_mode() == KMAC128 || kdf_mode() == KMAC256; }

      size_t pk_length() const;

      size_t sk_length() const;

      AlgorithmIdentifier algorithm_identifier() const;

      static std::string algorithm_name() { return "OunsworthKEMCombiner"; }

   private:
      std::vector<Sub_Algo> m_sub_algos;
      Kdf_Type m_kdf;
};

}  // namespace Botan::Ounsworth

#endif  // BOTAN_OUNSWORTH_MODE_H_
