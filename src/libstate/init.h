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

/**
* This class represents options for initializing the library.
*/
class BOTAN_DLL InitializerOptions
   {
   public:
      /**
      * Check whether this set of options has thread safety enabled.
      * @return true if thread safety is enabled
      */
      bool thread_safe() const;

      /**
      * Check whether this set of options has the usage of alternative engines
      * enabled.
      * @return true if the usage of alternative engines
      * is enabled
      */
      bool use_engines() const;

      /**
      * Check whether this set of options has enabled the memory
      * locking feature. This is implemented for Unix and Win32, but
      * it only reliably works for Unix. There, all SecureVectors and
      * SecureBuffers are kept from being ever swapped to disk. On
      * Win32 plattforms, the corresponding pages are locked into the
      * working set of the process, reducing the chance of being
      * swapped to disk, but not strictly preventing it.
      * @return true if the memory locking feature is enabled
      */
      bool secure_memory() const;

      /**
      * Check whether this set of options has the self-test-at-startup
      * enabled.  Same as self_test().
      * @param return true if the self-test is enabled
      */
      bool fips_mode() const;

      /**
      * Check whether this set of options has the self-test-at-startup enabled.
      * Same as fips_mode().
      * @param return true if the self-test is enabled
      */
      bool self_test() const;

      /**
      * Get the full path of the configuration file to be used.
      */
      std::string config_file() const;

      /**
      * Create an initializer options object. The option are set based on the
      * input string. The options can be set by building a white space separated
      * list of elements out of the
      * following set of strings:
      * "config=<file name>",
      * "selftest",
      * "fips140",
      * "use_engines",
      * "secure_memory",
      * "thread_safe"
      *
      */
      InitializerOptions(const std::string& options);
   private:
      std::map<std::string, std::string> args;
   };

/**
* This class represents the Library Initialization/Shutdown Object. It has to
* exceed the lifetime of any Botan object used in an application.
*/
class BOTAN_DLL LibraryInitializer
   {
   public:
      static void initialize(const std::string& = "");
      static void initialize(const InitializerOptions&);
      static void deinitialize();

      /**
      * Construct a library initializer from a string. Does exactly the same
      * as if an InitializerOptions object created with that string was used as
      * the argument.
      * @param args the string determining the desired library configuration
      */
      LibraryInitializer(const std::string& args = "") { initialize(args); }

      /**
      * Construct a library initializer.
      * @param args the initializer option object specifying the desired
      * library configuration
      */
      LibraryInitializer(const InitializerOptions& args) { initialize(args); }

      ~LibraryInitializer() { deinitialize(); }
   };

}

#endif
