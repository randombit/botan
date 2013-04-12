/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <iostream>
#include <iomanip>

#include <botan/benchmark.h>
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

   /* Cipher constructions */
   "Cascade(Serpent,AES-128)",
   "Lion(SHA-256,Salsa20,8192)",
   "Luby-Rackoff(SHA-512)",

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
   "ARC4",
   "Salsa20",

   /* Checksums */
   "Adler32",
   "CRC24",
   "CRC32",

   /* Hashes */
   "BMW-512",
   "GOST-34.11",
   "HAS-160",
   "Keccak-1600(224)",
   "Keccak-1600(256)",
   "Keccak-1600(384)",
   "Keccak-1600(512)",
   "MD2",
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
   "X9.19-MAC",
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

}

bool bench_algo(const std::string& algo,
                Botan::RandomNumberGenerator& rng,
                double seconds,
                u32bit buf_size)
   {
   Botan::Algorithm_Factory& af = Botan::global_state().algorithm_factory();

   std::chrono::milliseconds ms(
      static_cast<std::chrono::milliseconds::rep>(seconds * 1000));

   std::map<std::string, double> speeds =
      algorithm_benchmark(algo, af, rng, ms, buf_size);

   if(speeds.empty()) // maybe a cipher mode, then?
      {
      Botan::Algorithm_Factory::Engine_Iterator i(af);

      std::vector<std::string> algo_parts = Botan::split_on(algo, '/');

      if(algo_parts.size() < 2) // not a cipher mode
         return false;

      std::string cipher = algo_parts[0];

      const Botan::BlockCipher* proto_cipher =
         af.prototype_block_cipher(cipher);

      if(!proto_cipher)
         {
         std::cout << "Unknown algorithm " << cipher << "\n";
         return false;
         }

      size_t cipher_keylen = proto_cipher->maximum_keylength();
      size_t cipher_ivlen = proto_cipher->block_size();

      // hacks!
      if(algo_parts[1] == "XTS")
         cipher_keylen *= 2;
      if(algo_parts[1] == "OCB")
         cipher_ivlen -= 1;

      std::vector<byte> buf(16 * 1024);
      rng.randomize(&buf[0], buf.size());

      while(Botan::Engine* engine = i.next())
         {
         u64bit nanoseconds_max = static_cast<u64bit>(seconds * 1000000000.0);

         Botan::Keyed_Filter* filt =
            engine->get_cipher(algo, Botan::ENCRYPTION, af);

         if(!filt)
            continue;

         filt->set_key(Botan::SymmetricKey(&buf[0], cipher_keylen));

         if(filt->valid_iv_length(cipher_ivlen / 2))
           filt->set_iv(Botan::InitializationVector(&buf[0], cipher_ivlen));

         Botan::Pipe pipe(filt, new Botan::BitBucket);
         pipe.start_msg();

         std::chrono::nanoseconds max_time(nanoseconds_max);
         std::chrono::nanoseconds time_used(0);

         auto start = benchmark_clock::now();

         u64bit reps = 0;

         while(time_used < max_time)
            {
            pipe.write(&buf[0], buf.size());
            ++reps;
            time_used = benchmark_clock::now() - start;
            }

         u64bit nanoseconds_used =
            std::chrono::duration_cast<std::chrono::nanoseconds>(time_used).count();

         double mbytes_per_second =
            (953.67 * (buf.size() * reps)) / nanoseconds_used;

         speeds[engine->provider_name()] = mbytes_per_second;
         }
      }

   if(!speeds.empty())
      report_results(algo, speeds);

   return !speeds.empty();
   }

void benchmark(Botan::RandomNumberGenerator& rng,
               double seconds, u32bit buf_size)
   {
   for(u32bit i = 0; algos[i] != ""; ++i)
      bench_algo(algos[i], rng, seconds, buf_size);
   }
