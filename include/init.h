/*************************************************
* Library Initialization Header File             *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_INIT_H__
#define BOTAN_INIT_H__

#include <string>
#include <map>

namespace Botan {

/*************************************************
* Options for initializing the library           *
*************************************************/
class InitializerOptions
   {
   public:
      bool thread_safe() const;
      bool use_engines() const;
      bool seed_rng() const;
      bool secure_memory() const;
      bool fips_mode() const;
      bool self_test() const;

      std::string config_file() const;

      InitializerOptions(const std::string&);
   private:
      std::map<std::string, std::string> args;
   };

/*************************************************
* Library Initialization/Shutdown Object         *
*************************************************/
class LibraryInitializer
   {
   public:
      LibraryInitializer(const std::string& = "");
      LibraryInitializer(const InitializerOptions&);
      ~LibraryInitializer();
   };

namespace Init {

/*************************************************
* Main Library Initialization/Shutdown Functions *
*************************************************/
void initialize(const InitializerOptions&);
void deinitialize();

}


}

#endif
