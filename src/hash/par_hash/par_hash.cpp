/*
* Parallel
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/par_hash.h>
#include <botan/parsing.h>

namespace Botan {

/*
* Update the hash
*/
void Parallel::add_data(const byte input[], size_t length)
   {
   for(auto hash : hashes)
       hash->update(input, length);
   }

/*
* Finalize the hash
*/
void Parallel::final_result(byte out[])
   {
   u32bit offset = 0;

   for(auto hash : hashes)
      {
      hash->final(out + offset);
      offset += hash->output_length();
      }
   }

/*
* Return output size
*/
size_t Parallel::output_length() const
   {
   size_t sum = 0;

   for(auto hash : hashes)
      sum += hash->output_length();
   return sum;
   }

/*
* Return the name of this type
*/
std::string Parallel::name() const
   {
   std::vector<std::string> names;

   for(auto hash : hashes)
      names.push_back(hash->name());

   return "Parallel(" + string_join(names, ',') + ")";
   }

/*
* Return a clone of this object
*/
HashFunction* Parallel::clone() const
   {
   std::vector<HashFunction*> hash_copies;

   for(auto hash : hashes)
      hash_copies.push_back(hash->clone());

   return new Parallel(hash_copies);
   }

/*
* Clear memory of sensitive data
*/
void Parallel::clear()
   {
   for(auto hash : hashes)
      hash->clear();
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
   for(auto hash : hashes)
      delete hash;
   }

}
