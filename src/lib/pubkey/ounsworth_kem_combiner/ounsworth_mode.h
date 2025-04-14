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
#include <botan/kdf.h>
#include <botan/mac.h>
#include <botan/pk_algs.h>

#include <functional>

namespace Botan::Ounsworth {

/**
 * @brief Defines one of the options for the KDF used in the Ounsworth KEM Combiner.
 */
class BOTAN_UNSTABLE_API Kdf {
   public:
      enum class Option { KMAC128, KMAC256, SHA3_256, SHA3_512 };

      Kdf(Option type) : m_type(type) {}

      bool is_mac_based() const { return m_type == Option::KMAC128 || m_type == Option::KMAC256; }

      Option type() const { return m_type; }

      std::unique_ptr<Botan::KDF> create_kdf_instance() const;

   private:
      Option m_type;
};

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
 * @brief Specifies how to generate a new private key from raw key material.
 */
class BOTAN_UNSTABLE_API PrivateKeyGenerationInfo {
   public:
      /**
       * @brief Define the private key generation information for a predefined type.
       *
       * This constructor creates the generation info automatically from intern Botan information.
       * Using this constuctor is the easiest way to define a software key instance that is contained
       * in the Sub_Algo_Type list.
       *
       * @param algo the predefined sub-algorithm type
       */
      PrivateKeyGenerationInfo(Sub_Algo_Type algo);

      /**
       * @brief Define the generation info for a custom key type.
       *
       * @param create_private_key_callback A callback for creating a secret key using the output of raw_private_key_bits()
       */
      PrivateKeyGenerationInfo(
         std::function<std::unique_ptr<Private_Key>(RandomNumberGenerator&)> create_private_key_callback) :
            m_create_private_key_callback(std::move(create_private_key_callback)) {}

      std::unique_ptr<Private_Key> create_private_key(RandomNumberGenerator& rng) const {
         return m_create_private_key_callback(rng);
      }

   private:
      std::function<std::unique_ptr<Private_Key>(RandomNumberGenerator&)> m_create_private_key_callback;
};

/**
 * @brief Specifies how to import a private key from raw key material.
 */
class BOTAN_UNSTABLE_API PrivateKeyImportInfo {
   public:
      /**
       * @brief Define the private key import information for a predefined type.
       *
       * This constructor creates the import info automatically from intern Botan information.
       * Using this constuctor is the easiest way to define a software key instance that is contained
       * in the Sub_Algo_Type list.
       *
       * @param algo the predefined sub-algorithm type
       */
      PrivateKeyImportInfo(Sub_Algo_Type algo);

      /**
       * @brief Define the import info for a custom key type.
       *
       * @param load_private_key_callback A callback for loading a secret key using the output of raw_private_key_bits()
       * @param raw_sk_length The length of raw_private_key_bits() in bytes
       */
      PrivateKeyImportInfo(
         std::function<std::unique_ptr<Private_Key>(std::span<const uint8_t>)> load_private_key_callback,
         size_t raw_sk_length) :
            m_load_private_key_callback(std::move(load_private_key_callback)), m_raw_sk_length(raw_sk_length) {}

      std::unique_ptr<Private_Key> load_private_key(std::span<const uint8_t> key_data) const {
         return m_load_private_key_callback(key_data);
      }

      size_t raw_sk_length() const { return m_raw_sk_length; }

   private:
      std::function<std::unique_ptr<Private_Key>(std::span<const uint8_t>)> m_load_private_key_callback;
      size_t m_raw_sk_length;
};

/**
 * @brief Specifies how to import a public key from raw key material.
 */
class BOTAN_UNSTABLE_API PublicKeyImportInfo {
   public:
      /**
       * @brief Define the private key import information for a predefined type.
       *
       * This constructor creates the import info automatically from intern Botan information.
       * Using this constuctor is the easiest way to define a software key instance that is contained
       * in the Sub_Algo_Type list.
       *
       * @param algo the predefined sub-algorithm type
       */
      PublicKeyImportInfo(Sub_Algo_Type algo);

      /**
       * @brief Define the import info for a custom key type.
       *
       * @param load_public_key_callback A callback for loading a public key using the output of raw_public_key_bits()
       * @param raw_pk_length The length of raw_public_key_bits() in bytes
       */
      PublicKeyImportInfo(std::function<std::unique_ptr<Public_Key>(std::span<const uint8_t>)> load_public_key_callback,
                          size_t raw_pk_length) :
            m_load_public_key_callback(std::move(load_public_key_callback)), m_raw_pk_length(raw_pk_length) {}

      std::unique_ptr<Public_Key> load_public_key(std::span<const uint8_t> key_data) const {
         return m_load_public_key_callback(key_data);
      }

      size_t raw_pk_length() const { return m_raw_pk_length; }

   private:
      std::function<std::unique_ptr<Public_Key>(std::span<const uint8_t>)> m_load_public_key_callback;
      size_t m_raw_pk_length;
};

}  // namespace Botan::Ounsworth

#endif  // BOTAN_OUNSWORTH_MODE_H_
