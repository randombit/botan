/*
* No-Op Mutex Factory
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_NOOP_MUTEX_FACTORY_H__
#define BOTAN_NOOP_MUTEX_FACTORY_H__

#include <botan/internal/mutex.h>

namespace Botan {

/**
* No-Op Mutex Factory
*/
class Noop_Mutex_Factory : public Mutex_Factory
   {
   public:
      Mutex* make();
   };

}

#endif
