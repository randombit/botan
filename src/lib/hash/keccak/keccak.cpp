/*
* Keccak
* (C) 2010,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/keccak.h>

#include <botan/internal/sha3.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/fmt.h>
#include <botan/exceptn.h>

namespace Botan {

std::unique_ptr<HashFunction> Keccak_1600::copy_state() const
   {
   return std::make_unique<Keccak_1600>(*this);
   }

Keccak_1600::Keccak_1600(size_t output_bits) :
   m_output_bits(output_bits),
   m_bitrate(1600 - 2*output_bits),
   m_S(25),
   m_S_pos(0)
   {
   // We only support the parameters for the SHA-3 proposal

   if(output_bits != 224 && output_bits != 256 &&
      output_bits != 384 && output_bits != 512)
      {
      throw Invalid_Argument(fmt("Keccak_1600: Invalid output length {}", output_bits));
      }
   }

std::string Keccak_1600::name() const
   {
   return fmt("Keccak-1600({})", m_output_bits);
   }

std::unique_ptr<HashFunction> Keccak_1600::new_object() const
   {
   return std::make_unique<Keccak_1600>(m_output_bits);
   }

void Keccak_1600::clear()
   {
   zeroise(m_S);
   m_S_pos = 0;
   }

void Keccak_1600::add_data(const uint8_t input[], size_t length)
   {
   m_S_pos = SHA_3::absorb(m_bitrate, m_S, m_S_pos, input, length);
   }

void Keccak_1600::final_result(uint8_t output[])
   {
   SHA_3::finish(m_bitrate, m_S, m_S_pos, 0x01, 0x80);

   /*
   * We never have to run the permutation again because we only support
   * limited output lengths
   */
   copy_out_vec_le(output, m_output_bits/8, m_S);

   clear();
   }

}
