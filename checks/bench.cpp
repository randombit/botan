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
#include <botan/time.h>
#include <botan/hex.h>

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
   "TripleDES/CBC/PKCS7",
   "TripleDES/CBC/CTS",
   "TripleDES/CTR-BE",
   "TripleDES/EAX",
   "TripleDES/OFB",
   "TripleDES/CFB(64)",
   "TripleDES/CFB(32)",
   "TripleDES/CFB(16)",
   "TripleDES/CFB(8)",

   "AES-128/CBC/PKCS7",
   "AES-128/CBC/CTS",
   "AES-128/CTR-BE",
   "AES-128/EAX",
   "AES-128/OFB",
   "AES-128/XTS",
   "AES-128/CFB(128)",
   "AES-128/CFB(64)",
   "AES-128/CFB(32)",
   "AES-128/CFB(16)",
   "AES-128/CFB(8)",

   "Serpent/CBC/PKCS7",
   "Serpent/CBC/CTS",
   "Serpent/CTR-BE",
   "Serpent/EAX",
   "Serpent/OFB",
   "Serpent/XTS",
   "Serpent/CFB(128)",
   "Serpent/CFB(64)",
   "Serpent/CFB(32)",
   "Serpent/CFB(16)",
   "Serpent/CFB(8)",

   /* Stream ciphers */
   "ARC4",
   "Salsa20",
   "Turing",
   "WiderWake4+1-BE",

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

   for(std::map<std::string, double>::const_iterator i = speeds.begin();
       i != speeds.end(); ++i)
      {
      // Speeds might collide, tweak slightly to handle this
      if(results[i->second] == "")
         results[i->second] = i->first;
      else
         results[i->second - .01] = i->first;
      }

   std::cout << algo;

#if (defined(__GNUC__) && __GNUC__ <= 3) || defined(__SUNPRO_CC) || defined(__ANDROID__)
   // Work around bug in various compilers where map rev iterators don't work
   for(std::map<double, std::string>::const_iterator i = results.begin(); i != results.end(); ++i)
#else
   for(std::map<double, std::string>::const_reverse_iterator i = results.rbegin(); i != results.rend(); ++i)
#endif
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

   u32bit milliseconds = static_cast<u32bit>(seconds * 1000);

   std::map<std::string, double> speeds =
      algorithm_benchmark(algo, af, rng, milliseconds, buf_size);

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
      const size_t cipher_ivlen = proto_cipher->block_size();

      if(algo_parts[1] == "XTS")
         cipher_keylen *= 2; // hack!

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

         const u64bit start = Botan::get_nanoseconds_clock();
         u64bit nanoseconds_used = 0;
         u64bit reps = 0;

         while(nanoseconds_used < nanoseconds_max)
            {
            pipe.write(&buf[0], buf.size());
            ++reps;
            nanoseconds_used = Botan::get_nanoseconds_clock() - start;
            }

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
