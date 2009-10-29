/**
* SIMD Assembly Engine
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SIMD_ENGINE_H__
#define BOTAN_SIMD_ENGINE_H__

#include <botan/engine.h>

namespace Botan {

class BOTAN_DLL SIMD_Engine : public Engine
   {
   public:
      std::string provider_name() const { return "sse2"; }
   private:
      BlockCipher* find_block_cipher(const SCAN_Name&,
                                     Algorithm_Factory&) const;

      HashFunction* find_hash(const SCAN_Name& reqeust,
                              Algorithm_Factory&) const;
   };

}

#endif
