/*
* x86-64 Assembly Implementation Engines
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_AMD64_ASM_ENGINE_H__
#define BOTAN_AMD64_ASM_ENGINE_H__

#include <botan/engine.h>

namespace Botan {

/**
* Engine for implementations that are x86-64 specific
*/
class AMD64_Assembler_Engine : public Engine
   {
   public:
      std::string provider_name() const { return "amd64"; }

      HashFunction* find_hash(const SCAN_Name& reqeust,
                              Algorithm_Factory&) const;
   };

}

#endif
