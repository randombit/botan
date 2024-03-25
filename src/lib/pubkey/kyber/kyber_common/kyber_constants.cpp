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

#if defined(BOTAN_HAS_KYBER)
   #include <botan/internal/kyber_modern.h>
#endif

#if defined(BOTAN_HAS_KYBER_90S)
   #include <botan/internal/kyber_90s.h>
#endif

namespace Botan {

KyberConstants::KyberConstants(KyberMode mode) : m_mode(mode) {
   switch(mode.mode()) {
      case KyberMode::Kyber512_R3:
      case KyberMode::Kyber512_90s:
         m_nist_strength = 128;
         m_k = 2;
         m_eta1 = 3;
         break;

      case KyberMode::Kyber768_R3:
      case KyberMode::Kyber768_90s:
         m_nist_strength = 192;
         m_k = 3;
         m_eta1 = 2;
         break;

      case KyberMode::Kyber1024_R3:
      case KyberMode::Kyber1024_90s:
         m_nist_strength = 256;
         m_k = 4;
         m_eta1 = 2;
         break;

      default:
         BOTAN_ASSERT_UNREACHABLE();
   }

#ifdef BOTAN_HAS_KYBER_90S
   if(mode.is_kyber_round3() && mode.is_90s()) {
      m_symmetric_primitives = std::make_unique<Kyber_90s_Symmetric_Primitives>();
   }
#endif

#ifdef BOTAN_HAS_KYBER
   if(mode.is_kyber_round3() && mode.is_modern()) {
      m_symmetric_primitives = std::make_unique<Kyber_Modern_Symmetric_Primitives>();
   }
#endif

   if(!m_symmetric_primitives) {
      throw Not_Implemented("requested Kyber mode is not enabled in this build");
   }
}

KyberConstants::~KyberConstants() = default;

}  // namespace Botan
