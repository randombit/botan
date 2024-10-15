/*
 * Crystals Dilithium Constants
 *
 * (C) 2022-2023 Jack Lloyd
 * (C) 2022      Manuel Glaser - Rohde & Schwarz Cybersecurity
 * (C) 2022-2023 Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/dilithium_constants.h>

#include <botan/internal/dilithium_keys.h>
#include <botan/internal/dilithium_symmetric_primitives.h>

namespace Botan {

namespace {
uint32_t public_key_hash_size(DilithiumMode mode) {
   switch(mode.mode()) {
      case DilithiumMode::ML_DSA_4x4:
      case DilithiumMode::ML_DSA_6x5:
      case DilithiumMode::ML_DSA_8x7:
         return 64;
      case DilithiumMode::Dilithium4x4:
      case DilithiumMode::Dilithium4x4_AES:
      case DilithiumMode::Dilithium6x5:
      case DilithiumMode::Dilithium6x5_AES:
      case DilithiumMode::Dilithium8x7:
      case DilithiumMode::Dilithium8x7_AES:
         return 32;
   }
   BOTAN_ASSERT_UNREACHABLE();
}

uint32_t commitment_hash_full_size(DilithiumMode mode) {
   switch(mode.mode()) {
      case DilithiumMode::Dilithium4x4:
      case DilithiumMode::Dilithium4x4_AES:
      case DilithiumMode::Dilithium6x5:
      case DilithiumMode::Dilithium6x5_AES:
      case DilithiumMode::Dilithium8x7:
      case DilithiumMode::Dilithium8x7_AES:
      case DilithiumMode::ML_DSA_4x4:
         return 32;
      case DilithiumMode::ML_DSA_6x5:
         return 48;
      case DilithiumMode::ML_DSA_8x7:
         return 64;
   }
   BOTAN_ASSERT_UNREACHABLE();
}

}  // namespace

DilithiumConstants::~DilithiumConstants() = default;

DilithiumConstants::DilithiumConstants(DilithiumMode mode) :
      m_mode(mode),
      m_public_key_hash_bytes(public_key_hash_size(m_mode)),
      m_commitment_hash_full_bytes(commitment_hash_full_size(m_mode)) {
   switch(m_mode.mode()) {
      case Botan::DilithiumMode::Dilithium4x4:
      case Botan::DilithiumMode::Dilithium4x4_AES:
      case Botan::DilithiumMode::ML_DSA_4x4:
         m_tau = DilithiumTau::_39;
         m_lambda = DilithiumLambda::_128;
         m_gamma1 = DilithiumGamma1::ToThe17th;
         m_gamma2 = DilithiumGamma2::Qminus1DevidedBy88;
         m_k = 4;
         m_l = 4;
         m_eta = DilithiumEta::_2;
         m_beta = DilithiumBeta::_78;
         m_omega = DilithiumOmega::_80;
         break;
      case Botan::DilithiumMode::Dilithium6x5:
      case Botan::DilithiumMode::Dilithium6x5_AES:
      case Botan::DilithiumMode::ML_DSA_6x5:
         m_tau = DilithiumTau::_49;
         m_lambda = DilithiumLambda::_192;
         m_gamma1 = DilithiumGamma1::ToThe19th;
         m_gamma2 = DilithiumGamma2::Qminus1DevidedBy32;
         m_k = 6;
         m_l = 5;
         m_eta = DilithiumEta::_4;
         m_beta = DilithiumBeta::_196;
         m_omega = DilithiumOmega::_55;
         break;
      case Botan::DilithiumMode::Dilithium8x7:
      case Botan::DilithiumMode::Dilithium8x7_AES:
      case Botan::DilithiumMode::ML_DSA_8x7:
         m_tau = DilithiumTau::_60;
         m_lambda = DilithiumLambda::_256;
         m_gamma1 = DilithiumGamma1::ToThe19th;
         m_gamma2 = DilithiumGamma2::Qminus1DevidedBy32;
         m_k = 8;
         m_l = 7;
         m_eta = DilithiumEta::_2;
         m_beta = DilithiumBeta::_120;
         m_omega = DilithiumOmega::_75;
         break;
      default:
         BOTAN_ASSERT_UNREACHABLE();
   }

   const auto s1_bytes = 32 * m_l * bitlen(2 * m_eta);
   const auto s2_bytes = 32 * m_k * bitlen(2 * m_eta);
   const auto t0_bytes = 32 * m_k * D;
   const auto t1_bytes = 32 * m_k * (bitlen(static_cast<uint32_t>(Q) - 1) - D);
   const auto z_bytes = 32 * m_l * (1 + bitlen(m_gamma1 - 1));
   const auto hint_bytes = m_omega + m_k;

   m_private_key_bytes =
      SEED_RHO_BYTES + SEED_SIGNING_KEY_BYTES + m_public_key_hash_bytes + s1_bytes + s2_bytes + t0_bytes;
   m_public_key_bytes = SEED_RHO_BYTES + t1_bytes;
   m_signature_bytes = m_commitment_hash_full_bytes + z_bytes + hint_bytes;
   m_serialized_commitment_bytes = 32 * m_k * bitlen(((Q - 1) / (2 * m_gamma2)) - 1);

   m_symmetric_primitives = Dilithium_Symmetric_Primitives_Base::create(*this);
   m_keypair_codec = Dilithium_Keypair_Codec::create(mode);
}

}  // namespace Botan
