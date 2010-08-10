/**
* Dynamically Loaded Object
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_DYNAMIC_LOADER_H__
#define BOTAN_DYNAMIC_LOADER_H__

#include <string>

namespace Botan {

class Dynamically_Loaded_Library
   {
   public:
      /**
      * Load a DLL (or fail with an exception)
      * @param lib_name name or path to a library
      */
      Dynamically_Loaded_Library(const std::string& lib_name);

      /**
      * Unload the DLL
      * @warning Any pointers returned by resolve()/resolve_symbol()
      * should not be used after this destructor runs.
      */
      ~Dynamically_Loaded_Library();

      /**
      * Load a symbol (or fail with an exception)
      * @param symbol names the symbol to load
      * @return address of the loaded symbol
      */
      void* resolve_symbol(const std::string& symbol);

      /**
      * Convenience function for casting symbol to the right type
      * @param symbol names the symbol to load
      * @return address of the loaded symbol
      */
      template<typename T>
      T resolve(const std::string& symbol)
         {
#if defined(__GNUC__) && __GNUC__ < 4
         return (T)(resolve_symbol(symbol));
#else
         return reinterpret_cast<T>(resolve_symbol(symbol));
#endif
         }

   private:
      std::string lib_name;
      void* lib;
   };

}

#endif
