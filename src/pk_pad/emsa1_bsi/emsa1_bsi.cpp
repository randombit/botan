/*
* EMSA1 BSI
* (C) 1999-2008 Jack Lloyd
*     2008 Falko Strenzke, FlexSecure GmbH
*
* Distributed under the terms of the Botan license
*/

#include <botan/emsa1_bsi.h>

namespace Botan {

/*
* EMSA1 BSI Encode Operation
*/
SecureVector<byte> EMSA1_BSI::encoding_of(const MemoryRegion<byte>& msg,
                                          u32bit output_bits,
                                          RandomNumberGenerator&)
   {
   if(msg.size() != hash_ptr()->OUTPUT_LENGTH)
      throw Encoding_Error("EMSA1_BSI::encoding_of: Invalid size for input");

   if(8*msg.size() <= output_bits)
      return msg;

   throw Encoding_Error("EMSA1_BSI::encoding_of: max key input size exceeded");
   }

}
