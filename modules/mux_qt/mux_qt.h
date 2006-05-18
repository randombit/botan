/*************************************************
* Qt Thread Mutex Header File                    *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_EXT_MUTEX_QT_H__
#define BOTAN_EXT_MUTEX_QT_H__

#include <botan/mutex.h>

namespace Botan {

/*************************************************
* Qt Mutex                                       *
*************************************************/
class Qt_Mutex : public Mutex
   {
   public:
      void lock();
      void unlock();
      Mutex* clone() const { return new Qt_Mutex; }

      Qt_Mutex();
      ~Qt_Mutex();
   private:
      struct mutex_wrapper* mutex;
   };

}

#endif
