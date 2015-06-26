/*
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"

#if defined(BOTAN_HAS_RUNTIME_BENCHMARKING)

#include "speed.h"
#include <iostream>
#include <iomanip>

#include <botan/benchmark.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/parsing.h>
#include <botan/symkey.h>
#include <botan/transform.h>
#include <botan/hex.h>

#include <chrono>

typedef std::chrono::high_resolution_clock benchmark_clock;


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
   "HMAC(SHA-1)"
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

void time_transform(std::unique_ptr<Transform> tf,
                    RandomNumberGenerator& rng)
   {
   const std::chrono::seconds runtime(2);

   for(size_t buf_size : { 16, 64, 256, 1024, 8192 })
      {
      secure_vector<byte> buffer(buf_size);

      std::chrono::nanoseconds time_used(0);

      tf->start(rng.random_vec(tf->default_nonce_length()));

      auto start = std::chrono::high_resolution_clock::now();

      secure_vector<byte> buf(buf_size);
      size_t reps = 0;
      while(time_used < runtime)
         {
         tf->update(buf);
         buf.resize(buf_size);
         ++reps;
         time_used = std::chrono::high_resolution_clock::now() - start;
         }

      const u64bit nsec_used = std::chrono::duration_cast<std::chrono::nanoseconds>(time_used).count();

      const double seconds_used = static_cast<double>(nsec_used) / 1000000000;

      const double Mbps = ((reps / seconds_used) * buf_size) / 1024 / 1024;

      std::cout << tf->name() << " " << std::setprecision(4) << Mbps
                << " MiB / sec with " << buf_size << " byte blocks" << std::endl;
      }
   }

bool time_transform(const std::string& algo, RandomNumberGenerator& rng)
   {
   std::unique_ptr<Transform> tf;
   tf.reset(get_cipher_mode(algo, ENCRYPTION));
   if(!tf)
      return false;

   if(Keyed_Transform* keyed = dynamic_cast<Keyed_Transform*>(tf.get()))
      keyed->set_key(rng.random_vec(keyed->key_spec().maximum_keylength()));

   time_transform(std::move(tf), rng);
   return true;
   }

void bench_algo(const std::string& algo,
                RandomNumberGenerator& rng,
                double seconds,
                size_t buf_size)
   {
   std::chrono::milliseconds ms(
      static_cast<std::chrono::milliseconds::rep>(seconds * 1000));

   if(time_transform(algo, rng))
      return;

   std::map<std::string, double> speeds = algorithm_benchmark(algo, rng, ms, buf_size);

   if(!speeds.empty())
      {
      report_results(algo, speeds);
      return;
      }

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)
   bench_pk(rng, algo, seconds);
#endif
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
