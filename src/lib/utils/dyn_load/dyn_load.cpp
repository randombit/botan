/**
* Dynamically Loaded Object
* (C) 2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/dyn_load.h>
#include <botan/build.h>
#include <botan/exceptn.h>

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
   throw Exception("Failed to load " + lib_name + ": " +
                            (msg ? msg : "Unknown error"));
   }

}

Dynamically_Loaded_Library::Dynamically_Loaded_Library(
   const std::string& library) :
   m_lib_name(library), m_lib(nullptr)
   {
#if defined(BOTAN_TARGET_OS_HAS_DLOPEN)
   m_lib = ::dlopen(m_lib_name.c_str(), RTLD_LAZY);

   if(!m_lib)
      raise_runtime_loader_exception(m_lib_name, dlerror());

#elif defined(BOTAN_TARGET_OS_HAS_LOADLIBRARY)
   m_lib = ::LoadLibraryA(m_lib_name.c_str());

   if(!m_lib)
      raise_runtime_loader_exception(m_lib_name, "LoadLibrary failed");
#endif

   if(!m_lib)
      raise_runtime_loader_exception(m_lib_name, "Dynamic load not supported");
   }

Dynamically_Loaded_Library::~Dynamically_Loaded_Library()
   {
#if defined(BOTAN_TARGET_OS_HAS_DLOPEN)
   ::dlclose(m_lib);
#elif defined(BOTAN_TARGET_OS_HAS_LOADLIBRARY)
   ::FreeLibrary((HMODULE)m_lib);
#endif
   }

void* Dynamically_Loaded_Library::resolve_symbol(const std::string& symbol)
   {
   void* addr = nullptr;

#if defined(BOTAN_TARGET_OS_HAS_DLOPEN)
   addr = ::dlsym(m_lib, symbol.c_str());
#elif defined(BOTAN_TARGET_OS_HAS_LOADLIBRARY)
   addr = reinterpret_cast<void*>(::GetProcAddress((HMODULE)m_lib,
                                                   symbol.c_str()));
#endif

   if(!addr)
      throw Exception("Failed to resolve symbol " + symbol +
                               " in " + m_lib_name);

   return addr;
   }

}
