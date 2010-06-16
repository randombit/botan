/*
* IA-32 Assembly Implementation Engines
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_IA32_ASM_ENGINE_H__
#define BOTAN_IA32_ASM_ENGINE_H__

#include <botan/engine.h>

namespace Botan {

/**
* Engine for x86-32 specific implementations
*/
class IA32_Assembler_Engine : public Engine
   {
   public:
      std::string provider_name() const { return "ia32"; }

      BlockCipher* find_block_cipher(const SCAN_Name&,
                                     Algorithm_Factory&) const;

      HashFunction* find_hash(const SCAN_Name& reqeust,
                              Algorithm_Factory&) const;
   };

}

#endif
