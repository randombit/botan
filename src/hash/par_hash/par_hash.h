/*
* Parallel Hash
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_PARALLEL_HASH_H__
#define BOTAN_PARALLEL_HASH_H__

#include <botan/hash.h>
#include <vector>

namespace Botan {

/*
* Parallel
*/
class BOTAN_DLL Parallel : public HashFunction
   {
   public:
      void clear() throw();
      std::string name() const;
      HashFunction* clone() const;

      Parallel(const std::vector<HashFunction*>&);
      ~Parallel();
   private:
      void add_data(const byte[], u32bit);
      void final_result(byte[]);
      std::vector<HashFunction*> hashes;
   };

}

#endif
