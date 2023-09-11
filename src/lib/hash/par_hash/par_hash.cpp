/*
* Parallel Hash
* (C) 1999-2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/par_hash.h>

#include <botan/internal/stl_util.h>

#include <sstream>

namespace Botan {

void Parallel::add_data(std::span<const uint8_t> input) {
   for(auto&& hash : m_hashes) {
      hash->update(input);
   }
}

void Parallel::final_result(std::span<uint8_t> output) {
   BufferStuffer out(output);
   for(auto&& hash : m_hashes) {
      hash->final(out.next(hash->output_length()));
   }
}

size_t Parallel::output_length() const {
   size_t sum = 0;

   for(auto&& hash : m_hashes) {
      sum += hash->output_length();
   }
   return sum;
}

std::string Parallel::name() const {
   std::ostringstream name;

   name << "Parallel(";

   for(size_t i = 0; i != m_hashes.size(); ++i) {
      if(i != 0) {
         name << ",";
      }
      name << m_hashes[i]->name();
   }

   name << ")";

   return name.str();
}

std::unique_ptr<HashFunction> Parallel::new_object() const {
   std::vector<std::unique_ptr<HashFunction>> hash_copies;
   hash_copies.reserve(m_hashes.size());

   for(auto&& hash : m_hashes) {
      hash_copies.push_back(std::unique_ptr<HashFunction>(hash->new_object()));
   }

   return std::make_unique<Parallel>(hash_copies);
}

std::unique_ptr<HashFunction> Parallel::copy_state() const {
   std::vector<std::unique_ptr<HashFunction>> hash_new_objects;
   hash_new_objects.reserve(m_hashes.size());

   for(const auto& hash : m_hashes) {
      hash_new_objects.push_back(hash->copy_state());
   }

   return std::make_unique<Parallel>(hash_new_objects);
}

void Parallel::clear() {
   for(auto&& hash : m_hashes) {
      hash->clear();
   }
}

Parallel::Parallel(std::vector<std::unique_ptr<HashFunction>>& hashes) {
   m_hashes.reserve(hashes.size());
   for(auto&& hash : hashes) {
      m_hashes.push_back(std::move(hash));
   }
}

}  // namespace Botan
