/*
* Symmetric Algorithm Base Class
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ALGO_BASE_CLASS_H__
#define BOTAN_ALGO_BASE_CLASS_H__

#include <botan/build.h>
#include <string>

namespace Botan {

/**
* This class represents a symmetric algorithm object.
*/
class BOTAN_DLL Algorithm
   {
   public:

      /**
      * Make a new object representing the same algorithm as *this
      */
      virtual Algorithm* clone() const = 0;

      /**
      * Zeroize internal state
      */
      virtual void clear() = 0;

      /**
      * @return name of this algorithm
      */
      virtual std::string name() const = 0;

      Algorithm() {}
      virtual ~Algorithm() {}
   private:
      Algorithm(const Algorithm&) {}
      Algorithm& operator=(const Algorithm&) { return (*this); }
   };

}

#endif
