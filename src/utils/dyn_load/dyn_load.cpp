/**
* Dynamically Loaded Object
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/dyn_load.h>
#include <botan/build.h>
#include <stdexcept>

#if defined(BOTAN_TARGET_OS_HAS_DLOPEN)
  #include <dlfcn.h>
#endif

namespace Botan {

Dynamically_Loaded_Library::Dynamically_Loaded_Library(
   const std::string& library) :
   lib_name(library), lib(0)
   {
#if defined(BOTAN_TARGET_OS_HAS_DLOPEN)
   lib = ::dlopen(lib_name.c_str(), RTLD_LAZY);

   if(!lib)
      throw std::runtime_error("Failed to load engine " + lib_name);
#endif

   }

Dynamically_Loaded_Library::~Dynamically_Loaded_Library()
   {
#if defined(BOTAN_TARGET_OS_HAS_DLOPEN)
   ::dlclose(lib);
#endif
   }

void* Dynamically_Loaded_Library::resolve_symbol(const std::string& symbol)
   {
   void* addr = 0;

#if defined(BOTAN_TARGET_OS_HAS_DLOPEN)
   addr = ::dlsym(lib, symbol.c_str());
#endif

   if(!addr)
      throw std::runtime_error("Failed to resolve symbol " + symbol +
                               " in " + lib_name);

   return addr;
   }

}
