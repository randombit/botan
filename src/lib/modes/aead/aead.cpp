/*
* (C) 2013,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/mode_utils.h>
#include <botan/aead.h>

namespace Botan {

AEAD_Mode* get_aead(const std::string& algo_spec, Cipher_Dir direction)
   {
   std::unique_ptr<Cipher_Mode> mode(get_cipher_mode(algo_spec, direction));

   if(AEAD_Mode* aead = dynamic_cast<AEAD_Mode*>(mode.get()))
      {
      mode.release();
      return aead;
      }

   return nullptr;
   }

}
