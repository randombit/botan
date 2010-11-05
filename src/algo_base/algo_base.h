/*
* Algorithm Base Class
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ALGO_BASE_CLASS_H__
#define BOTAN_ALGO_BASE_CLASS_H__

#include <botan/build.h>
#include <string>

namespace Botan {

/**
* This class represents an algorithm of some kind
*/
class BOTAN_DLL Algorithm
   {
   public:

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
