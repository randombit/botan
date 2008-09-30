/*************************************************
* Library Initialization Header File             *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_INIT_H__
#define BOTAN_INIT_H__

#include <botan/build.h>
#include <string>
#include <map>

namespace Botan {

/*************************************************
* Options for initializing the library           *
*************************************************/
class BOTAN_DLL InitializerOptions
   {
   public:
      bool thread_safe() const;
      bool use_engines() const;
      bool secure_memory() const;
      bool fips_mode() const;
      bool self_test() const;

      InitializerOptions(const std::string&);
   private:
      std::map<std::string, std::string> args;
   };

/*************************************************
* Library Initialization/Shutdown Object         *
*************************************************/
class BOTAN_DLL LibraryInitializer
   {
   public:
      static void initialize(const std::string& = "");
      static void initialize(const InitializerOptions&);
      static void initialize(const InitializerOptions&, class Modules&);
      static void deinitialize();

      LibraryInitializer(const std::string& args = "") { initialize(args); }
      LibraryInitializer(const InitializerOptions& args) { initialize(args); }
      ~LibraryInitializer() { deinitialize(); }
   };

}

#endif
