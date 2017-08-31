/*
* Parallel Hash
* (C) 1999-2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/par_hash.h>
#include <botan/parsing.h>

namespace Botan {

void Parallel::add_data(const uint8_t input[], size_t length)
   {
   for(auto&& hash : m_hashes)
       hash->update(input, length);
   }

void Parallel::final_result(uint8_t out[])
   {
   size_t offset = 0;

   for(auto&& hash : m_hashes)
      {
      hash->final(out + offset);
      offset += hash->output_length();
      }
   }

size_t Parallel::output_length() const
   {
   size_t sum = 0;

   for(auto&& hash : m_hashes)
      sum += hash->output_length();
   return sum;
   }

std::string Parallel::name() const
   {
   std::vector<std::string> names;

   for(auto&& hash : m_hashes)
      names.push_back(hash->name());

   return "Parallel(" + string_join(names, ',') + ")";
   }

HashFunction* Parallel::clone() const
   {
   std::vector<std::unique_ptr<HashFunction>> hash_copies;

   for(auto&& hash : m_hashes)
      hash_copies.push_back(std::unique_ptr<HashFunction>(hash->clone()));

   return new Parallel(hash_copies);
   }

std::unique_ptr<HashFunction> Parallel::copy_state() const
   {
   std::vector<std::unique_ptr<HashFunction>> hash_clones;

   for(const std::unique_ptr<HashFunction>& hash : m_hashes)
      {
      hash_clones.push_back(hash->copy_state());
      }

   return std::unique_ptr<HashFunction>(new Parallel(hash_clones));
   }

void Parallel::clear()
   {
   for(auto&& hash : m_hashes)
      hash->clear();
   }

Parallel::Parallel(std::vector<std::unique_ptr<HashFunction>>& h)
   {
   for(size_t i = 0; i != h.size(); ++i)
      {
      m_hashes.push_back(std::unique_ptr<HashFunction>(h[i].release()));
      }
   }


}
