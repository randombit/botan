/*
* EMSA-Raw
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/emsa_raw.h>

namespace Botan {

/*
* EMSA-Raw Encode Operation
*/
void EMSA_Raw::update(const uint8_t input[], size_t length)
   {
   m_message += std::make_pair(input, length);
   }

/*
* Return the raw (unencoded) data
*/
secure_vector<uint8_t> EMSA_Raw::raw_data()
   {
   secure_vector<uint8_t> output;
   std::swap(m_message, output);
   return output;
   }

/*
* EMSA-Raw Encode Operation
*/
secure_vector<uint8_t> EMSA_Raw::encoding_of(const secure_vector<uint8_t>& msg,
                                         size_t,
                                         RandomNumberGenerator&)
   {
   return msg;
   }

/*
* EMSA-Raw Verify Operation
*/
bool EMSA_Raw::verify(const secure_vector<uint8_t>& coded,
                      const secure_vector<uint8_t>& raw,
                      size_t)
   {
   if(coded.size() == raw.size())
      return (coded == raw);

   if(coded.size() > raw.size())
      return false;

   // handle zero padding differences
   const size_t leading_zeros_expected = raw.size() - coded.size();

   bool same_modulo_leading_zeros = true;

   for(size_t i = 0; i != leading_zeros_expected; ++i)
      if(raw[i])
         same_modulo_leading_zeros = false;

   if(!same_mem(coded.data(), raw.data() + leading_zeros_expected, coded.size()))
      same_modulo_leading_zeros = false;

   return same_modulo_leading_zeros;
   }

}
