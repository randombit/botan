/*
* Parallel Hash
* (C) 1999-2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_utils.h>
#include <botan/par_hash.h>
#include <botan/parsing.h>
#include <botan/internal/algo_registry.h>

namespace Botan {

BOTAN_REGISTER_NAMED_T(HashFunction, "Parallel", Parallel, Parallel::make);

Parallel* Parallel::make(const Spec& spec)
   {
   auto& hash_fns = Algo_Registry<HashFunction>::global_registry();

   std::vector<std::unique_ptr<HashFunction>> hashes;

   for(size_t i = 0; i != spec.arg_count(); ++i)
      {
      std::unique_ptr<HashFunction> h(hash_fns.make(spec.arg(i)));

      if(!h)
         return nullptr;
      hashes.push_back(std::move(h));
      }

   Parallel* p = new Parallel;
   std::swap(p->hashes, hashes);
   return p;
   }

void Parallel::add_data(const byte input[], size_t length)
   {
   for(auto&& hash : hashes)
       hash->update(input, length);
   }

void Parallel::final_result(byte out[])
   {
   u32bit offset = 0;

   for(auto&& hash : hashes)
      {
      hash->final(out + offset);
      offset += hash->output_length();
      }
   }

size_t Parallel::output_length() const
   {
   size_t sum = 0;

   for(auto&& hash : hashes)
      sum += hash->output_length();
   return sum;
   }

std::string Parallel::name() const
   {
   std::vector<std::string> names;

   for(auto&& hash : hashes)
      names.push_back(hash->name());

   return "Parallel(" + string_join(names, ',') + ")";
   }

HashFunction* Parallel::clone() const
   {
   std::vector<HashFunction*> hash_copies;

   for(auto&& hash : hashes)
      hash_copies.push_back(hash->clone());

   return new Parallel(hash_copies);
   }

void Parallel::clear()
   {
   for(auto&& hash : hashes)
      hash->clear();
   }

Parallel::Parallel(const std::vector<HashFunction*>& in)
   {
   for(size_t i = 0; i != in.size(); ++i)
      {
      std::unique_ptr<HashFunction> h(in[i]->clone());
      hashes.push_back(std::move(h));
      }
   }


}
