/*
* SHA-3
* (C) 2010,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha3.h>
#include <botan/exceptn.h>

namespace Botan {

SHA_3::SHA_3(size_t output_bits) :
    Keccak_FIPS_generic("SHA-3", output_bits, 2*output_bits, 2, 2) 
   {
   // We only support the parameters for SHA-3 in this constructor

   if(output_bits != 224 && output_bits != 256 &&
      output_bits != 384 && output_bits != 512)
      throw Invalid_Argument("SHA_3: Invalid output length " +
                             std::to_string(output_bits));
   }

}

