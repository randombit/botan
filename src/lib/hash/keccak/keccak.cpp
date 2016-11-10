/*
* Keccak
* (C) 2010,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/keccak.h>
#include <botan/sha3.h>
#include <botan/parsing.h>
#include <botan/exceptn.h>

namespace Botan {

Keccak_1600::Keccak_1600(size_t output_bits) :
   m_output_bits(output_bits),
   m_bitrate(1600 - 2*output_bits),
   m_S(25),
   m_S_pos(0)
   {
   // We only support the parameters for the SHA-3 proposal

   if(output_bits != 224 && output_bits != 256 &&
      output_bits != 384 && output_bits != 512)
      throw Invalid_Argument("Keccak_1600: Invalid output length " +
                             std::to_string(output_bits));
   }

std::string Keccak_1600::name() const
   {
   return "Keccak-1600(" + std::to_string(m_output_bits) + ")";
   }

HashFunction* Keccak_1600::clone() const
   {
   return new Keccak_1600(m_output_bits);
   }

void Keccak_1600::clear()
   {
   zeroise(m_S);
   m_S_pos = 0;
   }

void Keccak_1600::add_data(const byte input[], size_t length)
   {
   m_S_pos = SHA_3::absorb(m_bitrate, m_S, m_S_pos, input, length);
   }

void Keccak_1600::final_result(byte output[])
   {
   std::vector<byte> padding(m_bitrate / 8 - m_S_pos);

   padding[0] = 0x01;
   padding[padding.size()-1] |= 0x80;

   add_data(padding.data(), padding.size());

   /*
   * We never have to run the permutation again because we only support
   * limited output lengths
   */
   for(size_t i = 0; i != m_output_bits/8; ++i)
      output[i] = get_byte(7 - (i % 8), m_S[i/8]);

   clear();
   }

}
