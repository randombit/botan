/*
* Comb4P hash combiner
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_COMB4P_H__
#define BOTAN_COMB4P_H__

#include <botan/hash.h>

namespace Botan {

/**
* Combines two hash functions using a Feistel scheme. Described in
* "On the Security of Hash Function Combiners", Anja Lehmann
*/
class BOTAN_DLL Comb4P : public HashFunction
   {
   public:
      /**
      * @param h1 the first hash
      * @param h2 the second hash
      */
      Comb4P(HashFunction* h1, HashFunction* h2);

      ~Comb4P() { delete hash1; delete hash2; }

      size_t hash_block_size() const;

      size_t output_length() const
         {
         return hash1->output_length() + hash2->output_length();
         }

      HashFunction* clone() const
         {
         return new Comb4P(hash1->clone(), hash2->clone());
         }

      std::string name() const
         {
         return "Comb4P(" + hash1->name() + "," + hash2->name() + ")";
         }

      void clear();
   private:
      void add_data(const byte input[], size_t length);
      void final_result(byte out[]);

      HashFunction* hash1;
      HashFunction* hash2;
   };

}

#endif
