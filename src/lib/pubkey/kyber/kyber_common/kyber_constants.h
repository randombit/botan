/*
 * Crystals Kyber Constants
 *
 * (C) 2021-2024 Jack Lloyd
 * (C) 2021-2022 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
 * (C) 2021-2022 René Meusel and Hannes Rantzsch, neXenio GmbH
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_KYBER_CONSTANTS_H_
#define BOTAN_KYBER_CONSTANTS_H_

#include <botan/kyber.h>

namespace Botan {

class Kyber_Symmetric_Primitives;
class Kyber_Keypair_Codec;

class KyberConstants final {
   public:
      /// base data type for most calculations
      using T = int16_t;

      /// number of coefficients in a polynomial
      static constexpr T N = 256;

      /// modulus
      static constexpr T Q = 3329;

      /// as specified in FIPS 203 (see Algorithm 10 (NTT^-1), f = 128^-1 mod Q)
      static constexpr T F = 3303;

      /// the primitive 256-th root of unity modulo Q (see FIPS 203 Section 4.3)
      static constexpr T ROOT_OF_UNITY = 17;

      /// degree of the NTT polynomials
      static constexpr size_t NTT_Degree = 128;

   public:
      static constexpr size_t SEED_BYTES = 32;
      static constexpr size_t PUBLIC_KEY_HASH_BYTES = 32;
      static constexpr size_t SHARED_KEY_BYTES = 32;

      /// sampling limit for SampleNTT (in bytes), see FIPS 204, Apx B
      static constexpr uint16_t SAMPLE_NTT_POLY_FROM_XOF_BOUND = 280 * 3 /* XOF bytes per while iteration */;

   public:
      enum KyberEta : uint8_t { _2 = 2, _3 = 3 };

      enum KyberDu : uint8_t { _10 = 10, _11 = 11 };

      enum KyberDv : uint8_t { _4 = 4, _5 = 5 };

      enum KyberStrength : uint32_t { _128 = 128, _192 = 192, _256 = 256 };

   public:
      KyberConstants(KyberMode mode);

      ~KyberConstants();

      KyberConstants(const KyberConstants& other) : KyberConstants(other.m_mode) {}

      KyberConstants(KyberConstants&& other) = default;
      KyberConstants& operator=(const KyberConstants& other) = delete;
      KyberConstants& operator=(KyberConstants&& other) = default;

      KyberMode mode() const { return m_mode; }

      /// @returns one of {512, 768, 1024}
      size_t canonical_parameter_set_identifier() const { return k() * N; }

      /// \name Foundational constants
      /// @{

      uint8_t k() const { return m_k; }

      KyberEta eta1() const { return m_eta1; }

      constexpr KyberEta eta2() const { return KyberEta::_2; }

      KyberDu d_u() const { return m_du; }

      KyberDv d_v() const { return m_dv; }

      KyberStrength estimated_strength() const { return m_nist_strength; }

      /// @}

      /// \name Sizes of encoded data structures
      /// @{

      /// byte length of an encoded polynomial vector
      size_t polynomial_vector_bytes() const { return m_polynomial_vector_bytes; }

      /// byte length of an encoded compressed polynomial vector
      size_t polynomial_vector_compressed_bytes() const { return m_polynomial_vector_compressed_bytes; }

      /// byte length of an encoded compressed polynomial
      size_t polynomial_compressed_bytes() const { return m_polynomial_compressed_bytes; }

      /// byte length of an encoded ciphertext
      size_t ciphertext_bytes() const { return polynomial_vector_compressed_bytes() + polynomial_compressed_bytes(); }

      /// byte length of the shared key
      constexpr size_t shared_key_bytes() const { return SHARED_KEY_BYTES; }

      /// byte length of an encoded public key
      size_t public_key_bytes() const { return polynomial_vector_bytes() + SEED_BYTES; }

      /// byte length of an encoded private key
      size_t private_key_bytes() const { return m_private_key_bytes; }

      /// @}

      Kyber_Symmetric_Primitives& symmetric_primitives() const { return *m_symmetric_primitives; }

      Kyber_Keypair_Codec& keypair_codec() const { return *m_keypair_codec; }

   private:
      KyberMode m_mode;

      KyberStrength m_nist_strength;
      KyberEta m_eta1;
      KyberDu m_du;
      KyberDv m_dv;
      uint8_t m_k;

      uint32_t m_polynomial_vector_bytes;
      uint32_t m_polynomial_vector_compressed_bytes;
      uint32_t m_polynomial_compressed_bytes;
      uint32_t m_private_key_bytes;

      std::unique_ptr<Kyber_Keypair_Codec> m_keypair_codec;
      std::unique_ptr<Kyber_Symmetric_Primitives> m_symmetric_primitives;
};

}  // namespace Botan

#endif
