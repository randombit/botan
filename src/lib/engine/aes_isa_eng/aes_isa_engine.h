/*
* Engine for AES instructions
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_AES_ISA_ENGINE_H__
#define BOTAN_AES_ISA_ENGINE_H__

#include <botan/engine.h>

namespace Botan {

/**
* Engine for implementations that hook into CPU-specific
* AES implementations (eg AES-NI, VIA C7, or AMD Geode)
*/
class AES_ISA_Engine : public Engine
   {
   public:
      std::string provider_name() const { return "aes_isa"; }

      BlockCipher* find_block_cipher(const SCAN_Name&,
                                     Algorithm_Factory&) const;
   };

}

#endif
