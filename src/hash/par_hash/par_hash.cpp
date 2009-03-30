/*
* Parallel
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/par_hash.h>

namespace Botan {

namespace {

/*
* Return the sum of the hash sizes
*/
u32bit sum_of_hash_lengths(const std::vector<HashFunction*>& hashes)
   {
   u32bit sum = 0;

   for(u32bit j = 0; j != hashes.size(); ++j)
      sum += hashes[j]->OUTPUT_LENGTH;

   return sum;
   }

}

/*
* Update the hash
*/
void Parallel::add_data(const byte input[], u32bit length)
   {
   for(u32bit j = 0; j != hashes.size(); ++j)
      hashes[j]->update(input, length);
   }

/*
* Finalize the hash
*/
void Parallel::final_result(byte hash[])
   {
   u32bit offset = 0;
   for(u32bit j = 0; j != hashes.size(); ++j)
      {
      hashes[j]->final(hash + offset);
      offset += hashes[j]->OUTPUT_LENGTH;
      }
   }

/*
* Return the name of this type
*/
std::string Parallel::name() const
   {
   std::string hash_names;
   for(u32bit j = 0; j != hashes.size(); ++j)
      {
      if(j)
         hash_names += ',';
      hash_names += hashes[j]->name();
      }
   return "Parallel(" + hash_names + ")";
   }

/*
* Return a clone of this object
*/
HashFunction* Parallel::clone() const
   {
   std::vector<HashFunction*> hash_copies;
   for(u32bit j = 0; j != hashes.size(); ++j)
      hash_copies.push_back(hashes[j]->clone());
   return new Parallel(hash_copies);
   }

/*
* Clear memory of sensitive data
*/
void Parallel::clear() throw()
   {
   for(u32bit j = 0; j != hashes.size(); ++j)
      hashes[j]->clear();
   }

/*
* Parallel Constructor
*/
Parallel::Parallel(const std::vector<HashFunction*>& hash_in) :
   HashFunction(sum_of_hash_lengths(hash_in)), hashes(hash_in)
   {
   }

/*
* Parallel Destructor
*/
Parallel::~Parallel()
   {
   for(u32bit j = 0; j != hashes.size(); ++j)
      delete hashes[j];
   }

}
