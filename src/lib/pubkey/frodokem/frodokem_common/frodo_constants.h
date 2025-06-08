/*
 * FrodoKEM constants
 *
 * The Fellowship of the FrodoKEM:
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_FRODOKEM_CONSTANTS_H_
#define BOTAN_FRODOKEM_CONSTANTS_H_

#include <botan/frodo_mode.h>
#include <botan/internal/frodo_types.h>

#include <memory>
#include <string>
#include <vector>

namespace Botan {

class XOF;

class BOTAN_TEST_API FrodoKEMConstants final {
   public:
      FrodoKEMConstants(FrodoKEMMode mode);

      ~FrodoKEMConstants();

      FrodoKEMConstants(const FrodoKEMConstants& other) : FrodoKEMConstants(other.m_mode) {}

      FrodoKEMConstants(FrodoKEMConstants&& other) = default;
      FrodoKEMConstants& operator=(const FrodoKEMConstants& other) = delete;
      FrodoKEMConstants& operator=(FrodoKEMConstants&& other) = default;

      FrodoKEMMode mode() const { return m_mode; }

      size_t cdf_table_len() const { return m_cdf_table.size(); }

      uint16_t cdf_table_at(size_t i) const { return m_cdf_table.at(i); }

      size_t estimated_strength() const { return m_nist_strength; }

      size_t n() const { return m_n; }

      size_t b() const { return m_b; }  // extracted bits

      size_t d() const { return m_d; }  // D = logq

      size_t n_bar() const { return m_n_bar; }

      size_t len_a_bytes() const { return m_len_a / 8; }  // len of seed_a in bytes

      size_t len_se_bytes() const { return m_len_se / 8; }

      size_t len_sec_bytes() const { return m_nist_strength / 8; }

      size_t len_salt_bytes() const { return m_len_salt / 8; }

      size_t len_ct_bytes() const {
         return (m_d * m_n * m_n_bar + m_d * m_n_bar * m_n_bar + m_len_salt) / 8;
      }  // Ciphertext length in bytes

      size_t len_public_key_bytes() const { return (m_len_a + (m_d * m_n * m_n_bar)) / 8; }

      size_t len_private_key_bytes() const {
         return (m_nist_strength + m_len_a + (m_d * m_n * m_n_bar) + (m_n_bar * m_n * 16) + m_nist_strength) / 8;
      }

      size_t len_packed_b_bytes() const { return (m_d * m_n * m_n_bar) / 8; }

      size_t len_packed_c_bytes() const { return (m_d * m_n_bar * m_n_bar) / 8; }

      FrodoDomainSeparator encapsulation_domain_separator() const { return FrodoDomainSeparator({0x96}); }

      FrodoDomainSeparator keygen_domain_separator() const { return FrodoDomainSeparator({0x5F}); }

      // TODO: those aren't actually const. We worked around some constness
      //       issues when playing with the XOFs that are residing in this class.
      XOF& SHAKE_XOF() const;

   private:
      FrodoKEMMode m_mode;
      size_t m_nist_strength;
      size_t m_len_salt;
      size_t m_len_se;
      size_t m_len_a;
      size_t m_b;
      size_t m_n;
      size_t m_n_bar;
      size_t m_d;

      std::vector<uint16_t> m_cdf_table;  // Distribution table T_chi

      mutable std::unique_ptr<XOF> m_shake_xof;

      std::string m_shake;
};

}  // namespace Botan

#endif
