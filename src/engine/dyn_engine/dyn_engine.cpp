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
   typedef Engine* (*creator_function)(void);
   typedef void (*destructor_function)(Engine*);
}

}

Dynamically_Loaded_Engine::Dynamically_Loaded_Engine(
   const std::string& library_path) :
   engine(0)
   {
   lib = new Dynamically_Loaded_Library(library_path);

   try
      {
      creator_function creator = lib->resolve<creator_function>("create_engine");

      engine = creator();

      if(!engine)
         throw std::runtime_error("Creator function in " + library_path + " failed");
      }
   catch(...)
      {
      delete lib;
      lib = 0;
      throw;
      }
   }

Dynamically_Loaded_Engine::~Dynamically_Loaded_Engine()
   {
   if(lib && engine)
      {
      try
         {
         destructor_function destroy =
            lib->resolve<destructor_function>("destroy_engine");
         destroy(engine);
         }
      catch(...)
         {
         delete lib;
         lib = 0;
         throw;
         }
      }

   if(lib)
      delete lib;
   }

}
