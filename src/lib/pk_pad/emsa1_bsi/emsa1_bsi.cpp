/*
* EMSA1 BSI
* (C) 1999-2008 Jack Lloyd
*     2008 Falko Strenzke, FlexSecure GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/emsa1_bsi.h>

namespace Botan {

EMSA* EMSA1_BSI::clone()
   {
   return new EMSA1_BSI(m_hash->clone());
   }


/*
* EMSA1 BSI Encode Operation
*/
secure_vector<byte> EMSA1_BSI::encoding_of(const secure_vector<byte>& msg,
                                          size_t output_bits,
                                          RandomNumberGenerator&)
   {
   if(msg.size() != hash_output_length())
      throw Encoding_Error("EMSA1_BSI::encoding_of: Invalid size for input");

   if(8*msg.size() <= output_bits)
      return msg;

   throw Encoding_Error("EMSA1_BSI::encoding_of: max key input size exceeded");
   }

}
