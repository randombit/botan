/*
* SHAKE-128/256 as a hash
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/shake.h>
#include <botan/sha3.h>
#include <botan/exceptn.h>

namespace Botan {

SHAKE_128::SHAKE_128(size_t output_bits) :
   m_output_bits(output_bits), m_S(25), m_S_pos(0)
   {
   if(output_bits % 8 != 0)
      throw Invalid_Argument("SHAKE_128: Invalid output length " +
                             std::to_string(output_bits));
   }

std::string SHAKE_128::name() const
   {
   return "SHAKE-128(" + std::to_string(m_output_bits) + ")";
   }

HashFunction* SHAKE_128::clone() const
   {
   return new SHAKE_128(m_output_bits);
   }

std::unique_ptr<HashFunction> SHAKE_128::copy_state() const
   {
   return std::unique_ptr<HashFunction>(new SHAKE_128(*this));
   }

void SHAKE_128::clear()
   {
   zeroise(m_S);
   m_S_pos = 0;
   }

void SHAKE_128::add_data(const uint8_t input[], size_t length)
   {
   m_S_pos = SHA_3::absorb(SHAKE_128_BITRATE, m_S, m_S_pos, input, length);
   }

void SHAKE_128::final_result(uint8_t output[])
   {
   SHA_3::finish(SHAKE_128_BITRATE, m_S, m_S_pos, 0x1F, 0x80);
   SHA_3::expand(SHAKE_128_BITRATE, m_S, output, output_length());
   clear();
   }

SHAKE_256::SHAKE_256(size_t output_bits) :
   m_output_bits(output_bits), m_S(25), m_S_pos(0)
   {
   if(output_bits % 8 != 0)
      throw Invalid_Argument("SHAKE_256: Invalid output length " +
                             std::to_string(output_bits));
   }

std::string SHAKE_256::name() const
   {
   return "SHAKE-256(" + std::to_string(m_output_bits) + ")";
   }

HashFunction* SHAKE_256::clone() const
   {
   return new SHAKE_256(m_output_bits);
   }

std::unique_ptr<HashFunction> SHAKE_256::copy_state() const
   {
   return std::unique_ptr<HashFunction>(new SHAKE_256(*this));
   }

void SHAKE_256::clear()
   {
   zeroise(m_S);
   m_S_pos = 0;
   }

void SHAKE_256::add_data(const uint8_t input[], size_t length)
   {
   m_S_pos = SHA_3::absorb(SHAKE_256_BITRATE, m_S, m_S_pos, input, length);
   }

void SHAKE_256::final_result(uint8_t output[])
   {
   SHA_3::finish(SHAKE_256_BITRATE, m_S, m_S_pos, 0x1F, 0x80);
   SHA_3::expand(SHAKE_256_BITRATE, m_S, output, output_length());

   clear();
   }

}
