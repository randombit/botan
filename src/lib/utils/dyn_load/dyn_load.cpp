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
#elif defined(BOTAN_TARGET_OS_HAS_LOADLIBRARY)
  #include <windows.h>
#endif

namespace Botan {

namespace {

void raise_runtime_loader_exception(const std::string& lib_name,
                                    const char* msg)
   {
   throw std::runtime_error("Failed to load " + lib_name + ": " +
                            (msg ? msg : "Unknown error"));
   }

}

Dynamically_Loaded_Library::Dynamically_Loaded_Library(
   const std::string& library) :
   lib_name(library), lib(nullptr)
   {
#if defined(BOTAN_TARGET_OS_HAS_DLOPEN)
   lib = ::dlopen(lib_name.c_str(), RTLD_LAZY);

   if(!lib)
      raise_runtime_loader_exception(lib_name, dlerror());

#elif defined(BOTAN_TARGET_OS_HAS_LOADLIBRARY)
   lib = ::LoadLibraryA(lib_name.c_str());

   if(!lib)
      raise_runtime_loader_exception(lib_name, "LoadLibrary failed");
#endif

   if(!lib)
      raise_runtime_loader_exception(lib_name, "Dynamic load not supported");
   }

Dynamically_Loaded_Library::~Dynamically_Loaded_Library()
   {
#if defined(BOTAN_TARGET_OS_HAS_DLOPEN)
   ::dlclose(lib);
#elif defined(BOTAN_TARGET_OS_HAS_LOADLIBRARY)
   ::FreeLibrary((HMODULE)lib);
#endif
   }

void* Dynamically_Loaded_Library::resolve_symbol(const std::string& symbol)
   {
   void* addr = nullptr;

#if defined(BOTAN_TARGET_OS_HAS_DLOPEN)
   addr = ::dlsym(lib, symbol.c_str());
#elif defined(BOTAN_TARGET_OS_HAS_LOADLIBRARY)
   addr = reinterpret_cast<void*>(::GetProcAddress((HMODULE)lib,
                                                   symbol.c_str()));
#endif

   if(!addr)
      throw std::runtime_error("Failed to resolve symbol " + symbol +
                               " in " + lib_name);

   return addr;
   }

}
