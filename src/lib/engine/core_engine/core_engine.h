/*
* Core Engine
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CORE_ENGINE_H__
#define BOTAN_CORE_ENGINE_H__

#include <botan/engine.h>

namespace Botan {

/**
* Core Engine
*/
class Core_Engine : public Engine
   {
   public:
      std::string provider_name() const override { return "core"; }

      BlockCipher* find_block_cipher(const SCAN_Name&,
                                     Algorithm_Factory&) const override;

      StreamCipher* find_stream_cipher(const SCAN_Name&,
                                       Algorithm_Factory&) const override;

      HashFunction* find_hash(const SCAN_Name& request,
                              Algorithm_Factory&) const override;

      MessageAuthenticationCode* find_mac(const SCAN_Name& request,
                                          Algorithm_Factory&) const override;

      PBKDF* find_pbkdf(const SCAN_Name& algo_spec,
                        Algorithm_Factory& af) const override;
   };

}

#endif
