/*************************************************
* Qt Mutex Header File                           *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_EXT_MUTEX_QT_H__
#define BOTAN_EXT_MUTEX_QT_H__

#include <botan/mutex.h>

namespace Botan {

/*************************************************
* Qt Mutex                                       *
*************************************************/
class Qt_Mutex_Factory : public Mutex_Factory
   {
   public:
      Mutex* make();
   };

}

#endif
