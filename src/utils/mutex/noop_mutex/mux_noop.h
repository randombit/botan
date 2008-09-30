/*************************************************
* No-Op Mutex Factory Header File                *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_NOOP_MUTEX_FACTORY_H__
#define BOTAN_NOOP_MUTEX_FACTORY_H__

#include <botan/mutex.h>

namespace Botan {

/*************************************************
* No-Op Mutex Factory                            *
*************************************************/
class BOTAN_DLL Noop_Mutex_Factory : public Mutex_Factory
   {
   public:
      Mutex* make();
   };

}

#endif
