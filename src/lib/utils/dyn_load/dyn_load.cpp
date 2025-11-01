/*
* Dynamically Loaded Object
* (C) 2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/dyn_load.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>
#include <botan/internal/target_info.h>
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

[[noreturn]] void raise_runtime_loader_exception(std::string_view lib_name, const char* msg) {
   std::ostringstream err;
   err << "Failed to load " << lib_name << ": ";
   if(msg != nullptr) {
      err << msg;
   } else {
      err << "Unknown error";
   }

   throw System_Error(err.str(), 0);
}

void* open_shared_library(const std::string& library) {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   void* lib = ::dlopen(library.c_str(), RTLD_LAZY);

   if(lib != nullptr) {
      return lib;
   } else {
      raise_runtime_loader_exception(library, ::dlerror());
   }

#elif defined(BOTAN_TARGET_OS_HAS_WIN32)
   void* lib = ::LoadLibraryA(library.c_str());

   if(lib != nullptr) {
      return lib;
   } else {
      raise_runtime_loader_exception(library, "LoadLibrary failed");
   }
#else
   raise_runtime_loader_exception(library, "Dynamic loading not supported");
#endif
}

}  // namespace

Dynamically_Loaded_Library::Dynamically_Loaded_Library(std::string_view library) :
      m_lib_name(library), m_lib(open_shared_library(m_lib_name)) {}

Dynamically_Loaded_Library::~Dynamically_Loaded_Library() {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   ::dlclose(m_lib);
#elif defined(BOTAN_TARGET_OS_HAS_WIN32)
   ::FreeLibrary(reinterpret_cast<HMODULE>(m_lib));
#endif
}

void* Dynamically_Loaded_Library::resolve_symbol(const std::string& symbol) const {
   if(void* addr = resolve_symbol_internal(symbol)) {
      return addr;
   }
   throw Invalid_Argument(fmt("Failed to resolve symbol {} in {}", symbol, m_lib_name));
}

void* Dynamically_Loaded_Library::resolve_symbol_internal(const std::string& symbol) const {
   void* addr = nullptr;
#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   addr = ::dlsym(m_lib, symbol.c_str());
#elif defined(BOTAN_TARGET_OS_HAS_WIN32)
   addr = reinterpret_cast<void*>(::GetProcAddress(reinterpret_cast<HMODULE>(m_lib), symbol.c_str()));
#endif

   return addr;
}

}  // namespace Botan
