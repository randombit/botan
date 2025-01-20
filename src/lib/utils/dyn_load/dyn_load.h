/*
* Dynamically Loaded Object
* (C) 2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DYNAMIC_LOADER_H_
#define BOTAN_DYNAMIC_LOADER_H_

#include <botan/types.h>
#include <optional>
#include <string>

namespace Botan {

/**
* Represents a DLL or shared object
*/
class BOTAN_TEST_API Dynamically_Loaded_Library final {
   public:
      /**
      * Load a DLL (or fail with an exception)
      * @param lib_name name or path to a library
      *
      * If you don't use a full path, the search order will be defined
      * by whatever the system linker does by default. Always using fully
      * qualified pathnames can help prevent code injection attacks (eg
      * via manipulation of LD_LIBRARY_PATH on Linux)
      */
      Dynamically_Loaded_Library(std::string_view lib_name);

      /**
      * Unload the DLL
      * @warning Any pointers returned by resolve()/resolve_symbol()
      * should not be used after this destructor runs.
      */
      ~Dynamically_Loaded_Library();

      /**
      * Try to load a symbol
      * @param symbol names the symbol to load
      * @return address of the loaded symbol or std::nullopt if the symbol
      *         was not found
      */
      template <typename PtrT>
      std::optional<PtrT> try_resolve_symbol(const std::string& symbol) const
         requires(std::is_pointer_v<PtrT>)
      {
         void* addr = resolve_symbol_internal(symbol);
         return addr ? std::optional(reinterpret_cast<PtrT>(addr)) : std::nullopt;
      }

      /**
      * Load a symbol (or fail with an exception)
      * @param symbol names the symbol to load
      * @return address of the loaded symbol
      * @throws Invalid_Argument if the symbol is not found
      */
      void* resolve_symbol(const std::string& symbol) const;

      /**
      * Convenience function for casting symbol to the right type
      * @param symbol names the symbol to load
      * @return address of the loaded symbol
      * @throws Invalid_Argument if the symbol is not found
      */
      template <typename PtrT>
      PtrT resolve(const std::string& symbol) const
         requires(std::is_pointer_v<PtrT>)
      {
         return reinterpret_cast<PtrT>(resolve_symbol(symbol));
      }

   private:
      /// Returns a pointer to the symbol or nullptr if the symbol is not found.
      void* resolve_symbol_internal(const std::string& symbol) const;

      Dynamically_Loaded_Library(const Dynamically_Loaded_Library&);
      Dynamically_Loaded_Library& operator=(const Dynamically_Loaded_Library&);

      std::string m_lib_name;
      void* m_lib;
};

}  // namespace Botan

#endif
