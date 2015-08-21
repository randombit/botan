/*
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"

#if defined(BOTAN_HAS_RUNTIME_BENCHMARKING)

#include "implementation/speed.h"

#include <iostream>
#include <iomanip>

#include <botan/benchmark.h>
#include <botan/auto_rng.h>

using namespace Botan;

namespace {
const std::vector<std::string> default_benchmark_list = {
   /* Block ciphers */
   "AES-128",
   "AES-192",
   "AES-256",
   "Blowfish",
   "CAST-128",
   "CAST-256",
   "DES",
   "IDEA",
   "KASUMI",
   "MARS",
   "MISTY1",
   "Noekeon",
   "RC2",
   "RC5(16)",
   "RC6",
   "SAFER-SK(10)",
   "SEED",
   "Serpent",
   "Skipjack",
   "Square",
   "TEA",
   "TripleDES",
   "Threefish-512",
   "Twofish",
   "XTEA",

   /* Cipher modes */
   "AES-128/CBC",
   "AES-128/CTR-BE",
   "AES-128/EAX",
   "AES-128/OCB",
   "AES-128/GCM",
   "AES-128/XTS",

   "Serpent/CBC",
   "Serpent/CTR-BE",
   "Serpent/EAX",
   "Serpent/OCB",
   "Serpent/GCM",
   "Serpent/XTS",

   /* Stream ciphers */
   "RC4",
   "Salsa20",

   /* Hashes */
   "Keccak-1600(512)",
   "MD5",
   "RIPEMD-160",
   "SHA-160",
   "SHA-256",
   "SHA-384",
   "SHA-512",
   "Skein-512",
   "Tiger",
   "Whirlpool",

   /* MACs */
   "CMAC(AES-128)",
   "HMAC(SHA-1)",

   /* Misc */
   "is_prime",
   "random_prime"
};

void report_results(const std::string& algo,
                    const std::map<std::string, double>& speeds)
   {
   if(speeds.empty())
      return;

   // invert, showing fastest impl first
   std::map<double, std::string> results;

   for(auto i = speeds.begin(); i != speeds.end(); ++i)
      {
      // Speeds might collide, tweak slightly to handle this
      if(results[i->second] == "")
         results[i->second] = i->first;
      else
         results[i->second - .01] = i->first;
      }

   std::cout << algo;

   const std::ios::fmtflags flags = std::cout.flags();
   for(auto i = results.rbegin(); i != results.rend(); ++i)
      {
      std::cout << " [" << i->second << "] "
                << std::fixed << std::setprecision(2) << i->first;
      }
   std::cout << std::endl;
   std::cout.flags(flags);
   }

void bench_algo(const std::string& algo,
                RandomNumberGenerator& rng,
                double seconds,
                size_t buf_size)
   {
   std::chrono::milliseconds runtime(
        static_cast<std::chrono::milliseconds::rep>(seconds * 1000));

   if (algo == "random_prime")
   {
       auto speeds = benchmark_random_prime(rng, runtime);
       report_results(algo, speeds);
       return;
   }

   if (algo == "is_prime")
   {
       auto speeds = benchmark_is_prime(rng, runtime);
       report_results(algo, speeds);
       return;
   }

   // This does report itself
   if (benchmark_transform(rng, algo, runtime))
      return;

   try
      {
      auto speeds = algorithm_benchmark(algo, rng, runtime, buf_size);
      report_results(algo, speeds);
      }
   catch (No_Provider_Found)
      {
      #if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)
      benchmark_public_key(rng, algo, seconds);
      #endif
      }
   }

int speed(int argc, char* argv[])
   {
   BOTAN_UNUSED(argc);
   OptionParser opts("seconds=|buf-size=");
   opts.parse(argv);

   double seconds = .5;
   u32bit buf_size = 16;

   if(opts.is_set("seconds"))
      {
      seconds = std::atof(opts.value("seconds").c_str());
      if(seconds < 0.1 || seconds > (5 * 60))
         {
         std::cout << "Invalid argument to --seconds" << std::endl;
         return 2;
         }
      }

   if(opts.is_set("buf-size"))
      {
      buf_size = std::atoi(opts.value("buf-size").c_str());
      if(buf_size == 0 || buf_size > 1024)
         {
         std::cout << "Invalid argument to --buf-size" << std::endl;
         return 2;
         }
      }

   auto args = opts.arguments();

   if(args.empty())
      args = default_benchmark_list;

   if(args[0] == "help" || args[0] == "-h")
      {
      std::cout << "Usage: " << argv[0] << " [algo name...]" << std::endl;
      return 1;
      }

   AutoSeeded_RNG rng;

   for(auto alg: args)
      bench_algo(alg, rng, seconds, buf_size);

   return 0;
   }

REGISTER_APP(speed);

}
#endif // BOTAN_HAS_RUNTIME_BENCHMARKING
