/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <iostream>
#include <iomanip>

#include <botan/benchmark.h>
#include <botan/aead.h>
#include <botan/libstate.h>
#include <botan/pipe.h>
#include <botan/filters.h>
#include <botan/engine.h>
#include <botan/parsing.h>
#include <botan/symkey.h>
#include <botan/hex.h>

#include <chrono>

typedef std::chrono::high_resolution_clock benchmark_clock;

#include "common.h"
#include "bench.h"

using namespace Botan;

namespace {

const std::string algos[] = {

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
   "RC5(12)",
   "RC5(16)",
   "RC6",
   "SAFER-SK(10)",
   "SEED",
   "Serpent",
   "Skipjack",
   "Square",
   "TEA",
   "TripleDES",
   "Twofish",
   "XTEA",

   /* Cipher modes */
   "AES-128/CBC/PKCS7",
   "AES-128/CTR-BE",
   "AES-128/EAX",
   "AES-128/OCB",
   "AES-128/GCM",
   "AES-128/XTS",

   "Serpent/CBC/PKCS7",
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
   "Keccak-1600(224)",
   "Keccak-1600(256)",
   "Keccak-1600(384)",
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
   "",
};

void report_results(const std::string& algo,
                    const std::map<std::string, double>& speeds)
   {
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

bool time_transform(const std::string& algo, RandomNumberGenerator& rng)
   {
   std::unique_ptr<Transformation> tf(get_aead(algo, ENCRYPTION));

   if(!tf)
      return false;

   tf->set_key(rng.random_vec(tf->maximum_keylength()));
   tf->start_vec(rng.random_vec(tf->default_nonce_length()));

   for(size_t mult : { 1, 2, 4, 8, 16, 128 })
      {
      const size_t buf_size = mult * tf->update_granularity();

      secure_vector<byte> buffer(buf_size);

      double res = time_op(std::chrono::seconds(1),
                           [&tf,&buffer,buf_size]{
                           tf->update(buffer);
                           buffer.resize(buf_size);
                           });

      const u64bit Mbytes = (res * buf_size) / 1024 / 1024;

      std::cout << algo << " " << Mbytes << " MiB / sec with " << buf_size << " byte blocks\n";
      }

   return true;
   }

}

bool bench_algo(const std::string& algo,
                RandomNumberGenerator& rng,
                double seconds,
                size_t buf_size)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();

   std::chrono::milliseconds ms(
      static_cast<std::chrono::milliseconds::rep>(seconds * 1000));

   std::map<std::string, double> speeds = algorithm_benchmark(algo, af, rng, ms, buf_size);

   if(!speeds.empty())
      {
      report_results(algo, speeds);
      return true;
      }

   return time_transform(algo, rng);
   }

void benchmark(RandomNumberGenerator& rng,
               double seconds, size_t buf_size)
   {
   for(size_t i = 0; algos[i] != ""; ++i)
      bench_algo(algos[i], rng, seconds, buf_size);
   }
