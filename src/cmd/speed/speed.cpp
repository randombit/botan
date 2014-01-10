/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include "speed.h"
#include <iostream>
#include <iomanip>

#include <botan/benchmark.h>
#include <botan/aead.h>
#include <botan/auto_rng.h>
#include <botan/libstate.h>
#include <botan/pipe.h>
#include <botan/filters.h>
#include <botan/engine.h>
#include <botan/parsing.h>
#include <botan/symkey.h>
#include <botan/hex.h>

#include <chrono>

typedef std::chrono::high_resolution_clock benchmark_clock;


using namespace Botan;

namespace {

const std::string default_benchmark_list[] = {

   /* Block ciphers */
   "AES-128",
   "AES-192",
   "AES-256",
   "Blowfish",
   "CAST-128",
   "CAST-256",
   "DES",
   "DESX",
   "GOST",
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
   "HAS-160",
   "Keccak-1600(512)",
   "MD4",
   "MD5",
   "RIPEMD-128",
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
   "",
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

   for(auto i = results.rbegin(); i != results.rend(); ++i)
      {
      std::cout << " [" << i->second << "] "
                << std::fixed << std::setprecision(2) << i->first;
      }
   std::cout << std::endl;
   }

void time_transform(std::unique_ptr<Transformation> tf,
                    RandomNumberGenerator& rng)
   {
   if(!tf)
      return;

   if(tf->maximum_keylength() > 0)
      tf->set_key(rng.random_vec(tf->maximum_keylength()));

   for(size_t buf_size : { 16, 64, 256, 1024, 8192 })
      {
      secure_vector<byte> buffer(buf_size);

      double res = time_op(std::chrono::seconds(1),
                           [&tf,&buffer,buf_size,&rng]{
                           tf->start_vec(rng.random_vec(tf->default_nonce_length()));
                           tf->finish(buffer);
                           buffer.resize(buf_size);
                           });

      const double Mbytes = (res * buf_size) / 1024 / 1024;

      std::cout << tf->name() << " " << std::setprecision(4) << Mbytes
                << " MiB / sec with " << buf_size << " byte blocks\n";
      }
   }

void time_transform(const std::string& algo, RandomNumberGenerator& rng)
   {
   std::unique_ptr<Transformation> tf;
   tf.reset(get_aead(algo, ENCRYPTION));
   time_transform(std::move(tf), rng);
   }

}

void bench_algo(const std::string& algo,
                RandomNumberGenerator& rng,
                double seconds,
                size_t buf_size)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();

   std::chrono::milliseconds ms(
      static_cast<std::chrono::milliseconds::rep>(seconds * 1000));

   std::map<std::string, double> speeds = algorithm_benchmark(algo, af, rng, ms, buf_size);

   report_results(algo, speeds);

   if(speeds.empty())
      time_transform(algo, rng);

   if(speeds.empty())
      bench_pk(rng, algo, seconds);
   }

int speed_main(int argc, char* argv[])
   {
   OptionParser opts("seconds=|buf-size=");
   opts.parse(argv);

   double seconds = .5;
   u32bit buf_size = 16;

   if(opts.is_set("seconds"))
      {
      seconds = std::atof(opts.value("seconds").c_str());
      if(seconds < 0.1 || seconds > (5 * 60))
         {
         std::cout << "Invalid argument to --seconds\n";
         return 2;
         }
      }

   if(opts.is_set("buf-size"))
      {
      buf_size = std::atoi(opts.value("buf-size").c_str());
      if(buf_size == 0 || buf_size > 1024)
         {
         std::cout << "Invalid argument to --buf-size\n";
         return 2;
         }
      }

   const auto args = opts.arguments();

   if(args.empty() || args[0] == "help" || args[0] == "-h")
      {
      std::cout << "Help!\n";
      return 1;
      }

   AutoSeeded_RNG rng;

   for(auto alg: args)
      bench_algo(alg, rng, seconds, buf_size);

   return 0;
   }
