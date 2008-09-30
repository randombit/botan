/*************************************************
* Pthread Mutex Header File                      *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_MUTEX_PTHREAD_H__
#define BOTAN_MUTEX_PTHREAD_H__

#include <botan/mutex.h>

namespace Botan {

/*************************************************
* Pthread Mutex Factory                          *
*************************************************/
class Pthread_Mutex_Factory : public Mutex_Factory
   {
   public:
      Mutex* make();
   };

}

#endif
