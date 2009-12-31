/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/numthry.h>
#include <botan/auto_rng.h>
#include <botan/botan.h>

using namespace Botan;

#include <set>
#include <iostream>
#include <iterator>
#include <map>

int main()
   {
   Botan::LibraryInitializer init;
   AutoSeeded_RNG rng;

   std::set<BigInt> primes;

   std::map<int, int> bit_count;

   int not_new = 0;

   while(primes.size() < 10000)
      {
      u32bit start_cnt = primes.size();

      u32bit bits = 18;

      if(rng.next_byte() % 128 == 0)
         bits -= rng.next_byte() % (bits-2);

      bit_count[bits]++;

      //std::cout << "random_prime(" << bits << ")\n";

      BigInt p = random_prime(rng, bits);

      if(p.bits() != bits)
         {
         std::cout << "Asked for " << bits << " got " << p 
                   << " " << p.bits() << " bits\n";
         return 1;
         }

      primes.insert(random_prime(rng, bits));

      if(primes.size() != start_cnt)
         std::cout << primes.size() << "\n";
      else
         not_new++;

      //std::cout << "miss: " << not_new << "\n";

      if(not_new % 100000 == 0)
         {
         for(std::map<int, int>::iterator i = bit_count.begin();
             i != bit_count.end(); ++i)
            std::cout << "bit_count[" << i->first << "] = "
                      << i->second << "\n";
         std::copy(primes.begin(), primes.end(),
                   std::ostream_iterator<BigInt>(std::cout, " "));
         }
      }

   std::cout << "Generated all? primes\n";
   /*
   for(u32bit j = 0; j != PRIME_TABLE_SIZE; ++j)
      {
      if(primes.count(PRIMES[j]) != 1)
         std::cout << "Missing " << PRIMES[j] << "\n";
      }
   */
   }
