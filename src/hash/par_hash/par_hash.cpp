/*
* Parallel
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/par_hash.h>

namespace Botan {

/*
* Update the hash
*/
void Parallel::add_data(const byte input[], size_t length)
   {
   for(size_t i = 0; i != hashes.size(); ++i)
      hashes[i]->update(input, length);
   }

/*
* Finalize the hash
*/
void Parallel::final_result(byte hash[])
   {
   size_t offset = 0;
   for(size_t i = 0; i != hashes.size(); ++i)
      {
      hashes[i]->final(hash + offset);
      offset += hashes[i]->output_length();
      }
   }

/*
* Return output size
*/
size_t Parallel::output_length() const
   {
   size_t sum = 0;
   for(size_t i = 0; i != hashes.size(); ++i)
      sum += hashes[i]->output_length();
   return sum;
   }

/*
* Return the name of this type
*/
std::string Parallel::name() const
   {
   std::string hash_names;
   for(size_t i = 0; i != hashes.size(); ++i)
      {
      if(i)
         hash_names += ',';
      hash_names += hashes[i]->name();
      }
   return "Parallel(" + hash_names + ")";
   }

/*
* Return a clone of this object
*/
HashFunction* Parallel::clone() const
   {
   std::vector<HashFunction*> hash_copies;
   for(size_t i = 0; i != hashes.size(); ++i)
      hash_copies.push_back(hashes[i]->clone());
   return new Parallel(hash_copies);
   }

/*
* Clear memory of sensitive data
*/
void Parallel::clear()
   {
   for(size_t i = 0; i != hashes.size(); ++i)
      hashes[i]->clear();
   }

/*
* Parallel Constructor
*/
Parallel::Parallel(const std::vector<HashFunction*>& hash_in) :
   hashes(hash_in)
   {
   }

/*
* Parallel Destructor
*/
Parallel::~Parallel()
   {
   for(size_t i = 0; i != hashes.size(); ++i)
      delete hashes[i];
   }

}
