/*
 * Ascon-XOF128 (NIST SP.800-232 Section 5.2)
 *
 * (C) 2025 Jack Lloyd
 *     2025 René Meusel
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/ascon_xof128.h>

#include <botan/assert.h>

namespace Botan {

namespace {

// NIST SP.800-232 Appendix A (Table 12)
constexpr Ascon_p initial_state_of_ascon_xof_permutation({
   .init_and_final_rounds = 12,
   .processing_rounds = 12,
   .bit_rate = 64,
   .initial_state =
      {
         0xda82ce768d9447eb,
         0xcc7ce6c75f1ef969,
         0xe7508fd780085631,
         0x0ee0ea53416b58cc,
         0xe0547524db6f0bde,
      },
});

}  // namespace

Ascon_XOF128::Ascon_XOF128() : m_ascon_p(initial_state_of_ascon_xof_permutation) {}

std::unique_ptr<XOF> Ascon_XOF128::copy_state() const {
   return std::make_unique<Ascon_XOF128>(*this);
}

std::unique_ptr<XOF> Ascon_XOF128::new_object() const {
   return std::make_unique<Ascon_XOF128>();
}

void Ascon_XOF128::add_data(std::span<const uint8_t> input) {
   BOTAN_STATE_CHECK(!m_output_generated);
   m_ascon_p.absorb(input);
}

void Ascon_XOF128::generate_bytes(std::span<uint8_t> output) {
   if(!m_output_generated) {
      m_output_generated = true;
      m_ascon_p.finish();
   }

   m_ascon_p.squeeze(output);
}

void Ascon_XOF128::reset() {
   m_ascon_p = initial_state_of_ascon_xof_permutation;
   m_output_generated = false;
}

}  // namespace Botan
