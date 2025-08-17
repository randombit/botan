/*
 * Ascon-XOF128 (NIST SP.800-232 Section 5.2)
 *
 * (C) 2025 Jack Lloyd
 *     2025 René Meusel
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_ASCON_XOF128_H_
#define BOTAN_ASCON_XOF128_H_

#include <botan/xof.h>
#include <botan/internal/ascon_perm.h>

namespace Botan {

/**
* Ascon-XOF128 (NIST SP.800-232 Section 5.2)
*/
class Ascon_XOF128 final : public XOF {
   public:
      Ascon_XOF128();

      std::string name() const override { return "Ascon-XOF128"; }

      std::string provider() const override { return m_ascon_p.provider(); }

      size_t block_size() const override { return m_ascon_p.byte_rate(); }

      bool accepts_input() const override { return !m_output_generated; }

      std::unique_ptr<XOF> copy_state() const override;
      std::unique_ptr<XOF> new_object() const override;

   private:
      void add_data(std::span<const uint8_t> input) override;
      void generate_bytes(std::span<uint8_t> output) override;
      void reset() override;

   private:
      Ascon_p m_ascon_p;
      bool m_output_generated = false;
};

}  // namespace Botan

#endif
