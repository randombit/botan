/*
* Dynamically Loaded Object
* (C) 2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/dyn_load.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>
#include <sstream>

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   #include <dlfcn.h>
#elif defined(BOTAN_TARGET_OS_HAS_WIN32)
   #define NOMINMAX 1
   #define _WINSOCKAPI_  // stop windows.h including winsock.h
   #include <windows.h>
#endif

namespace Botan {

namespace {

void raise_runtime_loader_exception(std::string_view lib_name, const char* msg) {
   std::ostringstream err;
   err << "Failed to load " << lib_name << ": ";
   if(msg) {
      err << msg;
   } else {
      err << "Unknown error";
   }

   throw System_Error(err.str(), 0);
}

}  // namespace

Dynamically_Loaded_Library::Dynamically_Loaded_Library(std::string_view library) : m_lib_name(library), m_lib(nullptr) {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   m_lib = ::dlopen(m_lib_name.c_str(), RTLD_LAZY);

   if(!m_lib) {
      raise_runtime_loader_exception(m_lib_name, ::dlerror());
   }

#elif defined(BOTAN_TARGET_OS_HAS_WIN32)
   m_lib = ::LoadLibraryA(m_lib_name.c_str());

   if(!m_lib)
      raise_runtime_loader_exception(m_lib_name, "LoadLibrary failed");
#endif

   if(!m_lib) {
      raise_runtime_loader_exception(m_lib_name, "Dynamic load not supported");
   }
}

Dynamically_Loaded_Library::~Dynamically_Loaded_Library() {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   ::dlclose(m_lib);
#elif defined(BOTAN_TARGET_OS_HAS_WIN32)
   ::FreeLibrary(reinterpret_cast<HMODULE>(m_lib));
#endif
}

void* Dynamically_Loaded_Library::resolve_symbol(const std::string& symbol) {
   void* addr = nullptr;

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   addr = ::dlsym(m_lib, symbol.c_str());
#elif defined(BOTAN_TARGET_OS_HAS_WIN32)
   addr = reinterpret_cast<void*>(::GetProcAddress(reinterpret_cast<HMODULE>(m_lib), symbol.c_str()));
#endif

   if(!addr) {
      throw Invalid_Argument(fmt("Failed to resolve symbol {} in {}", symbol, m_lib_name));
   }

   return addr;
}

}  // namespace Botan
