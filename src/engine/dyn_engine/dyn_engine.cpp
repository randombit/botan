/**
* Dynamically Loaded Engine
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/dyn_engine.h>
#include <botan/internal/dyn_load.h>

namespace Botan {

namespace {

extern "C" {
   typedef Engine* (*creator_func)(void);
   typedef u32bit (*module_version_func)(void);
}

}

Dynamically_Loaded_Engine::Dynamically_Loaded_Engine(
   const std::string& library_path) :
   engine(nullptr)
   {
   lib = new Dynamically_Loaded_Library(library_path);

   try
      {
      module_version_func get_version =
         lib->resolve<module_version_func>("module_version");

      const u32bit mod_version = get_version();

      if(mod_version != 20101003)
         throw std::runtime_error("Incompatible version in " +
                                  library_path + " of " +
                                  to_string(mod_version));

      creator_func creator =
         lib->resolve<creator_func>("create_engine");

      engine = creator();

      if(!engine)
         throw std::runtime_error("Creator function in " +
                                  library_path + " failed");
      }
   catch(...)
      {
      delete lib;
      lib = nullptr;
      throw;
      }
   }

Dynamically_Loaded_Engine::~Dynamically_Loaded_Engine()
   {
   delete engine;
   delete lib;
   }

}
