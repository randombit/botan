/*
 * Test Driver for Botan
 *
 * This file is in the public domain
 */

#include <vector>
#include <string>

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <exception>

#include <botan/botan.h>
#include <botan/mp_types.h>

/* Flag to use engine(s) for PK operations, if available */
#define USE_ENGINES 0

using namespace Botan_types;

/* Not on by default as many compilers (including egcs and gcc 2.95.x)
 * do not have the C++ <limits> header.
 *
 * At *some* point all OSes will have a reasonably recent GCC, but right now
 * GCC 2.95.x is the most recent compiler for a number of systems, including
 * OpenBSD, QNX, and BeOS.
 *
 */
//#define TEST_TYPES

#if defined(TEST_TYPES)
   #include <limits>
#endif

const std::string VALIDATION_FILE = "checks/validate.dat";
const std::string BIGINT_VALIDATION_FILE = "checks/mp_valid.dat";
const std::string PK_VALIDATION_FILE = "checks/pk_valid.dat";
const std::string EXPECTED_FAIL_FILE = "checks/fail.dat";

void benchmark(const std::string&, bool html, double seconds);
void bench_pk(const std::string&, bool html, double seconds);
u32bit bench_algo(const std::string&);
int validate();
void print_help(double);

int main(int argc, char* argv[])
   {
   try {

#if 0
      // Make sure we can repeatedly init/shutdown without problems
      for(u32bit j = 0; j != 3; j++)
         {
         Botan::Init::initialize();
         Botan::Init::deinitialize();
         }
#endif

      std::string init_flags = "";
      if(USE_ENGINES)
         init_flags += " use_engines";

      Botan::LibraryInitializer init(init_flags);
      bool html = false; // default to text output
      double seconds = 1.5;

      std::vector<std::string> args;
      for(int j = 1; j != argc; j++)
         args.push_back(argv[j]);

      if(!args.size()) { print_help(seconds); return 2; }

      for(u32bit j = 0; j != args.size(); j++)
         {
         if(args[j] == "--help") { print_help(seconds); return 1; }
         if(args[j] == "--html") html = true;
         if(args[j] == "--bench-algo")
            {
            if(j != args.size() - 1)
               {
               u32bit found = bench_algo(args[j+1]);
               if(!found) // maybe it's a PK algorithm
                  bench_pk(args[j+1], false, seconds);
               }
            else
               {
               std::cout << "Option --bench-algo needs an argument\n";
               return 2;
               }
            }
         if(args[j] == "--seconds")
            {
            if(j != args.size() - 1) // another arg remains
               {
               seconds = std::atof(args[j+1].c_str());
               // sanity check; we allow zero for testing porpoises
               if((seconds < 0.1 || seconds > 30) && seconds != 0)
                  {
                  std::cout << "Invalid argument to --seconds\n";
                  return 2;
                  }
               }
            else
               {
               std::cout << "Option --seconds needs an argument\n";
               return 2;
               }
            }
         }

      for(u32bit j = 0; j != args.size(); j++)
         {
         if(args[j] == "--validate")     return validate();
         if(args[j] == "--benchmark")    benchmark("All", html, seconds);
         if(args[j] == "--bench-all")    benchmark("All", html, seconds);
         if(args[j] == "--bench-block")
            benchmark("Block Cipher", html, seconds);
         if(args[j] == "--bench-mode")
            benchmark("Cipher Mode", html, seconds);
         if(args[j] == "--bench-stream")
            benchmark("Stream Cipher", html, seconds);
         if(args[j] == "--bench-hash")   benchmark("Hash", html, seconds);
         if(args[j] == "--bench-mac")    benchmark("MAC", html, seconds);
         if(args[j] == "--bench-rng")    benchmark("RNG", html, seconds);
         if(args[j] == "--bench-pk")     bench_pk("All", html, seconds);
         }
      }
   catch(Botan::Exception& e)
      {
      std::cout << "Exception caught:\n   " << e.what() << std::endl;
      return 1;
      }
   catch(std::exception& e)
      {
      std::cout << "Standard library exception caught:\n   "
                << e.what() << std::endl;
      return 1;
      }
   catch(...)
      {
      std::cout << "Unknown exception caught." << std::endl;
      return 1;
      }

   return 0;
   }

void print_help(double seconds)
   {
   std::cout << Botan::version_string() << " test driver" << std::endl
      << "Usage:\n"
      << "  --validate: Check test vectors\n"
      << "  --benchmark: Benchmark everything\n"
      << "  --bench-{block,mode,stream,hash,mac,rng,pk}:\n"
      << "         Benchmark only algorithms of a particular type\n"
      << "  --html: Produce HTML output for benchmarks\n"
      << "  --seconds n: Benchmark for n seconds (default is "
      <<       seconds << ")\n"
      << "  --help: Print this message\n";
   }

int validate()
   {
   void test_types();
   u32bit do_validation_tests(const std::string&, bool = true);
   u32bit do_bigint_tests(const std::string&);
   u32bit do_pk_validation_tests(const std::string&);

   std::cout << "Beginning validation tests..." << std::endl;

   test_types();
   u32bit errors = 0;
   try {
      errors += do_validation_tests(VALIDATION_FILE);
      errors += do_validation_tests(EXPECTED_FAIL_FILE, false);
      errors += do_bigint_tests(BIGINT_VALIDATION_FILE);
      errors += do_pk_validation_tests(PK_VALIDATION_FILE);
      }
   catch(Botan::Exception& e)
      {
      std::cout << "Exception caught: " << e.what() << std::endl;
      return 1;
      }
   catch(std::exception& e)
      {
      std::cout << "Standard library exception caught: "
                << e.what() << std::endl;
      return 1;
      }
   catch(...)
      {
      std::cout << "Unknown exception caught." << std::endl;
      return 1;
      }

   if(errors)
      {
      std::cout << errors << " test"  << ((errors == 1) ? "" : "s")
                << " failed." << std::endl;
      return 1;
      }

   std::cout << "All tests passed!" << std::endl;
   return 0;
   }

#if defined(TEST_TYPES)
template<typename T>
bool test(const char* type, u32bit digits, bool is_signed)
   {
   bool passed = true;
   if(std::numeric_limits<T>::is_specialized == false)
      {
      std::cout << "WARNING: Could not check parameters of " << type
                << " in std::numeric_limits" << std::endl;
      return true;
      }

   if(std::numeric_limits<T>::digits != digits && digits != 0)
      {
      std::cout << "ERROR: numeric_limits<" << type << ">::digits != "
                << digits << std::endl;
      passed = false;
      }
   if(std::numeric_limits<T>::is_signed != is_signed)
      {
      std::cout << "ERROR: numeric_limits<" << type << ">::is_signed != "
                << std::boolalpha << is_signed << std::endl;
      passed = false;
      }
   if(std::numeric_limits<T>::is_integer == false)
      {
      std::cout << "ERROR: numeric_limits<" << type
                << ">::is_integer == false " << std::endl;
      passed = false;
      }
   return passed;
   }
#endif

void test_types()
   {
   bool passed = true;

#if defined(TEST_TYPES)
   passed = passed && test<byte  >("byte",    8, false);
   passed = passed && test<u16bit>("u16bit", 16, false);
   passed = passed && test<u32bit>("u32bit", 32, false);
   passed = passed && test<u64bit>("u64bit", 64, false);
   passed = passed && test<s32bit>("s32bit", 31,  true);
   passed = passed && test<Botan::word>("word", 0, false);
#endif

   if(!passed)
      {
      std::cout << "Important settings in types.h are wrong. Please fix "
                   "and recompile." << std::endl;
      std::exit(1);
      }
   }
