/**
* SSE2 Assembly Engine
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SSE2_ASM_ENGINE_H__
#define BOTAN_SSE2_ASM_ENGINE_H__

#include <botan/engine.h>

namespace Botan {

class BOTAN_DLL SSE2_Assembler_Engine : public Engine
   {
   public:
      std::string provider_name() const { return "sse2"; }
   private:
      HashFunction* find_hash(const SCAN_Name& reqeust,
                              Algorithm_Factory&) const;
   };

}

#endif
