/**
* Hash Function Base Class
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_HASH_FUNCTION_BASE_CLASS_H__
#define BOTAN_HASH_FUNCTION_BASE_CLASS_H__

#include <botan/buf_comp.h>
#include <string>

namespace Botan {

/**
* This class represents hash function (message digest) objects.
*/
class BOTAN_DLL HashFunction : public BufferedComputation
   {
   public:
      /**
      * The hash block size as defined for this algorithm.
      */
      const u32bit HASH_BLOCK_SIZE;

      /**
      * Get a new object representing the same algorithm as *this
      */
      virtual HashFunction* clone() const = 0;

      /**
      * Get the name of this algorithm.
      * @return the name of this algorithm
      */
      virtual std::string name() const = 0;

      /**
      * Reset the internal state of this object.
      */
      virtual void clear() throw() = 0;

      HashFunction(u32bit hash_len, u32bit block_len = 0) :
         BufferedComputation(hash_len), HASH_BLOCK_SIZE(block_len) {}
      virtual ~HashFunction() {}
   private:
      HashFunction& operator=(const HashFunction&);
   };

}

#endif
