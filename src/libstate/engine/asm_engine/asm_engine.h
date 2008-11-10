/*************************************************
* Assembly Implementation Engine Header File     *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_ASM_ENGINE_H__
#define BOTAN_ASM_ENGINE_H__

#include <botan/engine.h>

namespace Botan {

class BOTAN_DLL Assembler_Engine : public Engine
   {
   public:
      std::string provider_name() const { return "asm"; }
   private:
      BlockCipher* find_block_cipher(const SCAN_Name&,
                                     Algorithm_Factory&) const;

      HashFunction* find_hash(const SCAN_Name& reqeust,
                              Algorithm_Factory&) const;
   };

}

#endif
