/*************************************************
* Qt Mutex Header File                           *
* (C) 2004-2007 Justin Karneges                  *
*     2004-2007 Jack Lloyd                       *
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
