/**
* Engine for AES instructions
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_AES_ISA_ENGINE_H__
#define BOTAN_AES_ISA_ENGINE_H__

#include <botan/engine.h>

namespace Botan {

class AES_ISA_Engine : public Engine
   {
   public:
      std::string provider_name() const { return "aes_isa"; }
   private:
      BlockCipher* find_block_cipher(const SCAN_Name&,
                                     Algorithm_Factory&) const;
   };

}

#endif
