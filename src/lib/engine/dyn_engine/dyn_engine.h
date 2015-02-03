/**
* Dynamically Loaded Engine
* (C) 2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DYN_LOADED_ENGINE_H__
#define BOTAN_DYN_LOADED_ENGINE_H__

#include <botan/engine.h>

namespace Botan {

/**
* Dynamically_Loaded_Engine just proxies the requests to the underlying
* Engine object, and handles load/unload details
*/
class BOTAN_DLL Dynamically_Loaded_Engine : public Engine
   {
   public:
      /**
      * @param lib_path full pathname to DLL to load
      */
      Dynamically_Loaded_Engine(const std::string& lib_path);

      Dynamically_Loaded_Engine(const Dynamically_Loaded_Engine&) = delete;

      Dynamically_Loaded_Engine& operator=(const Dynamically_Loaded_Engine&) = delete;

      ~Dynamically_Loaded_Engine();

      std::string provider_name() const override { return engine->provider_name(); }

      BlockCipher* find_block_cipher(const SCAN_Name& algo_spec,
                                     Algorithm_Factory& af) const override
         {
         return engine->find_block_cipher(algo_spec, af);
         }

      StreamCipher* find_stream_cipher(const SCAN_Name& algo_spec,
                                       Algorithm_Factory& af) const override
         {
         return engine->find_stream_cipher(algo_spec, af);
         }

      HashFunction* find_hash(const SCAN_Name& algo_spec,
                              Algorithm_Factory& af) const override
         {
         return engine->find_hash(algo_spec, af);
         }

      MessageAuthenticationCode* find_mac(const SCAN_Name& algo_spec,
                                          Algorithm_Factory& af) const override
         {
         return engine->find_mac(algo_spec, af);
         }

      PBKDF* find_pbkdf(const SCAN_Name& algo_spec,
                        Algorithm_Factory& af) const override
         {
         return engine->find_pbkdf(algo_spec, af);
         }

   private:
      class Dynamically_Loaded_Library* lib;
      Engine* engine;
   };

}

#endif
