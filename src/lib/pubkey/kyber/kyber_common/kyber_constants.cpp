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

#include <botan/internal/kyber_constants.h>

#include <botan/internal/pqcrystals_helpers.h>

#if defined(BOTAN_HAS_KYBER)
   #include <botan/internal/kyber_modern.h>
#endif

#if defined(BOTAN_HAS_KYBER_90S)
   #include <botan/internal/kyber_90s.h>
#endif

#if defined(BOTAN_HAS_KYBER) || defined(BOTAN_HAS_KYBER_90S)
   #include <botan/internal/kyber_round3_impl.h>
#endif

#if defined(BOTAN_HAS_ML_KEM)
   #include <botan/internal/ml_kem_impl.h>
#endif

namespace Botan {

KyberConstants::KyberConstants(KyberMode mode) : m_mode(mode) {
   switch(mode.mode()) {
      case KyberMode::Kyber512_R3:
      case KyberMode::Kyber512_90s:
      case KyberMode::ML_KEM_512:
         m_nist_strength = KyberStrength::_128;
         m_k = 2;
         m_eta1 = KyberEta::_3;
         m_du = KyberDu::_10;
         m_dv = KyberDv::_4;
         break;

      case KyberMode::Kyber768_R3:
      case KyberMode::Kyber768_90s:
      case KyberMode::ML_KEM_768:
         m_nist_strength = KyberStrength::_192;
         m_k = 3;
         m_eta1 = KyberEta::_2;
         m_du = KyberDu::_10;
         m_dv = KyberDv::_4;
         break;

      case KyberMode::Kyber1024_R3:
      case KyberMode::Kyber1024_90s:
      case KyberMode::ML_KEM_1024:
         m_nist_strength = KyberStrength::_256;
         m_k = 4;
         m_eta1 = KyberEta::_2;
         m_du = KyberDu::_11;
         m_dv = KyberDv::_5;
         break;

      default:
         BOTAN_ASSERT_UNREACHABLE();
   }

#ifdef BOTAN_HAS_KYBER_90S
   if(mode.is_kyber_round3() && mode.is_90s()) {
      m_symmetric_primitives = std::make_unique<Kyber_90s_Symmetric_Primitives>();
      m_keypair_codec = std::make_unique<Kyber_Expanded_Keypair_Codec>();
   }
#endif

#ifdef BOTAN_HAS_KYBER
   if(mode.is_kyber_round3() && mode.is_modern()) {
      m_symmetric_primitives = std::make_unique<Kyber_Modern_Symmetric_Primitives>();
      m_keypair_codec = std::make_unique<Kyber_Expanded_Keypair_Codec>();
   }
#endif

#ifdef BOTAN_HAS_ML_KEM
   if(mode.is_ml_kem()) {
      m_symmetric_primitives = std::make_unique<ML_KEM_Symmetric_Primitives>();
      m_keypair_codec = std::make_unique<ML_KEM_Expanding_Keypair_Codec>();
   }
#endif

   static_assert(N % 8 == 0);
   m_polynomial_vector_bytes = (bitlen(Q) * (N / 8)) * k();
   m_polynomial_vector_compressed_bytes = d_u() * k() * (N / 8);
   m_polynomial_compressed_bytes = d_v() * (N / 8);
   m_private_key_bytes = static_cast<uint32_t>([this]() -> size_t {
      if(m_mode.is_ml_kem()) {
         // ML-KEM's private keys are simply expanded from their seeds.
         return 2 * SEED_BYTES;
      } else {
         return m_polynomial_vector_bytes + public_key_bytes() + PUBLIC_KEY_HASH_BYTES + SEED_BYTES;
      }
   }());

   if(!m_symmetric_primitives) {
      throw Not_Implemented("requested Kyber mode is not enabled in this build");
   }
}

KyberConstants::~KyberConstants() = default;

}  // namespace Botan
