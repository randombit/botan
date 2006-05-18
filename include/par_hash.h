/*************************************************
* Parallel Header File                           *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_PAR_HASH_H__
#define BOTAN_PAR_HASH_H__

#include <botan/base.h>
#include <vector>

namespace Botan {

/*************************************************
* Parallel                                       *
*************************************************/
class Parallel : public HashFunction
   {
   public:
      void clear() throw();
      std::string name() const;
      HashFunction* clone() const;
      Parallel(const std::vector<std::string>&);
      ~Parallel();
   private:
      void add_data(const byte[], u32bit);
      void final_result(byte[]);
      std::vector<HashFunction*> hashes;
   };

}

#endif
