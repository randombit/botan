/*
 * FrodoKEM modes and constants
 *
 * The Fellowship of the FrodoKEM:
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/frodo_constants.h>

#include <botan/xof.h>

namespace Botan {

FrodoKEMConstants::FrodoKEMConstants(FrodoKEMMode mode) : m_mode(mode), m_len_a(128), m_n_bar(8) {
   if(!mode.is_available()) {
      throw Not_Implemented("FrodoKEM mode " + mode.to_string() + " is not available");
   }

   if(mode.is_ephemeral()) {
      m_len_salt = 0;
   }

   switch(mode.mode()) {
      case FrodoKEMMode::FrodoKEM640_SHAKE:
      case FrodoKEMMode::FrodoKEM640_AES:
      case FrodoKEMMode::eFrodoKEM640_SHAKE:
      case FrodoKEMMode::eFrodoKEM640_AES:
         m_nist_strength = 128;
         m_d = 15;
         m_n = 640;
         m_b = 2;
         if(mode.is_static()) {
            m_len_salt = 256;
            m_len_se = 256;
         } else if(mode.is_ephemeral()) {
            m_len_se = 128;
         } else {
            BOTAN_ASSERT_UNREACHABLE();
         }

         m_cdf_table = {4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767};

         m_shake = "SHAKE-128";
         break;

      case FrodoKEMMode::FrodoKEM976_SHAKE:
      case FrodoKEMMode::FrodoKEM976_AES:
      case FrodoKEMMode::eFrodoKEM976_SHAKE:
      case FrodoKEMMode::eFrodoKEM976_AES:
         m_nist_strength = 192;
         m_d = 16;
         m_n = 976;
         m_b = 3;
         if(mode.is_static()) {
            m_len_salt = 384;
            m_len_se = 384;
         } else if(mode.is_ephemeral()) {
            m_len_se = 192;
         } else {
            BOTAN_ASSERT_UNREACHABLE();
         }

         m_cdf_table = {5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767};

         m_shake = "SHAKE-256";
         break;

      case FrodoKEMMode::FrodoKEM1344_SHAKE:
      case FrodoKEMMode::FrodoKEM1344_AES:
      case FrodoKEMMode::eFrodoKEM1344_SHAKE:
      case FrodoKEMMode::eFrodoKEM1344_AES:
         m_nist_strength = 256;
         m_d = 16;
         m_n = 1344;
         m_b = 4;
         if(mode.is_static()) {
            m_len_salt = 512;
            m_len_se = 512;
         } else if(mode.is_ephemeral()) {
            m_len_se = 256;
         } else {
            BOTAN_ASSERT_UNREACHABLE();
         }

         m_cdf_table = {9142, 23462, 30338, 32361, 32725, 32765, 32767};

         m_shake = "SHAKE-256";
         break;
   }

   m_shake_xof = XOF::create_or_throw(m_shake);
}

FrodoKEMConstants::~FrodoKEMConstants() = default;

XOF& FrodoKEMConstants::SHAKE_XOF() const {
   m_shake_xof->clear();
   return *m_shake_xof;
}

}  // namespace Botan
