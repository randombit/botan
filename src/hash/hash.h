/*
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
      * @param hash_len the output length
      * @param block_len the internal block size (if applicable)
      */
      HashFunction(u32bit hash_len) : BufferedComputation(hash_len) {}

      virtual ~HashFunction() {}

      /**
      * Get a new object representing the same algorithm as *this
      */
      virtual HashFunction* clone() const = 0;

      /**
      * Get the name of this algorithm.
      * @return name of this algorithm
      */
      virtual std::string name() const = 0;

      /**
      * The hash block size as defined for this algorithm
      */
      virtual size_t hash_block_size() const { return 0; }

      /**
      * Reset the internal state of this object.
      */
      virtual void clear() = 0;

   private:
      HashFunction& operator=(const HashFunction&);
   };

}

#endif
