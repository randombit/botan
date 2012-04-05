/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/benchmark.h>
#include <botan/init.h>
#include <botan/auto_rng.h>
#include <botan/libstate.h>

using namespace Botan;

#include <iostream>

namespace {

const std::string algos[] = {
   "AES-128",
   "AES-192",
   "AES-256",
   "Blowfish",
   "CAST-128",
   "CAST-256",
   "DES",
   "DESX",
   "TripleDES",
   "GOST",
   "IDEA",
   "KASUMI",
   "Lion(SHA-256,Turing,8192)",
   "Luby-Rackoff(SHA-512)",
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
   "Twofish",
   "XTEA",
   "Adler32",
   "CRC32",
   "GOST-34.11",
   "HAS-160",
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
   "CMAC(AES-128)",
   "HMAC(SHA-1)",
   "X9.19-MAC",
   "",
};

void benchmark_algo(const std::string& algo,
                    RandomNumberGenerator& rng)
   {
   u32bit milliseconds = 1000;
   Algorithm_Factory& af = global_state().algorithm_factory();

   std::map<std::string, double> speeds =
      algorithm_benchmark(algo, af, rng, milliseconds, 16);

   std::cout << algo << ":";

   for(std::map<std::string, double>::const_iterator i = speeds.begin();
       i != speeds.end(); ++i)
      {
      std::cout << " " << i->second << " [" << i->first << "]";
      }
   std::cout << "\n";
   }

}

int main(int argc, char* argv[])
   {
   LibraryInitializer init;

   AutoSeeded_RNG rng;

   if(argc == 1) // no args, benchmark everything
      {
      for(u32bit i = 0; algos[i] != ""; ++i)
         benchmark_algo(algos[i], rng);
      }
   else
      {
      for(int i = 1; argv[i]; ++i)
         benchmark_algo(argv[i], rng);
      }
   }
