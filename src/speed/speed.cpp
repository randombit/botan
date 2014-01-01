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

std::map<std::string, double> time_transform(std::unique_ptr<Transformation> tf,
                                             RandomNumberGenerator& rng)
   {
   std::map<std::string, double> results;

   if(!tf)
      return results;

   if(tf->maximum_keylength() > 0)
      tf->set_key(rng.random_vec(tf->maximum_keylength()));

   tf->start_vec(rng.random_vec(tf->default_nonce_length()));


   for(size_t buf_size : { 16, 64, 256, 1024, 8192 })
      {
      secure_vector<byte> buffer(buf_size);

      double res = time_op(std::chrono::seconds(1),
                           [&tf,&buffer,buf_size]{
                           tf->finish(buffer);
                           buffer.resize(buf_size);
                           });

      const double Mbytes = (res * buf_size) / 1024 / 1024;

      results[""] = Mbytes;
      std::cout << tf->name() << " " << Mbytes << " MiB / sec with " << buf_size << " byte blocks\n";
      }

   return results;
   }

std::map<std::string, double> time_transform(const std::string& algo, RandomNumberGenerator& rng)
   {
   std::unique_ptr<Transformation> tf;
   tf.reset(get_aead(algo, ENCRYPTION));
   return time_transform(std::move(tf), rng);
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

   if(speeds.empty())
      speeds = time_transform(algo, rng);

   report_results(algo, speeds);

   if(speeds.empty())
      bench_pk(rng, algo, seconds);
   }

void benchmark(double seconds, size_t buf_size)
   {
   AutoSeeded_RNG rng;

   for(size_t i = 0; algos[i] != ""; ++i)
      bench_algo(algos[i], rng, seconds, buf_size);
   }

int speed_main(int , char* argv[])
   {
   OptionParser opts("algo=|seconds=|buf-size=");
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

   if(opts.is_set("algo"))
      {
      AutoSeeded_RNG rng;
      for(auto alg: Botan::split_on(opts.value("algo"), ','))
         bench_algo(alg, rng, seconds, buf_size);
      }
   else
      benchmark(seconds, buf_size);

   return 0;
   }
