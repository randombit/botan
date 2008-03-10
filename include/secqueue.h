/*************************************************
* SecureQueue Header File                        *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_SECURE_QUEUE_H__
#define BOTAN_SECURE_QUEUE_H__

#include <botan/data_src.h>
#include <botan/filter.h>

namespace Botan {

/*************************************************
* SecureQueue                                    *
*************************************************/
class SecureQueue : public Fanout_Filter, public DataSource
   {
   public:
      void write(const byte[], u32bit);

      u32bit read(byte[], u32bit);
      u32bit peek(byte[], u32bit, u32bit = 0) const;

      bool end_of_data() const;
      u32bit size() const;
      bool attachable() { return false; }

      SecureQueue& operator=(const SecureQueue&);
      SecureQueue();
      SecureQueue(const SecureQueue&);
      ~SecureQueue() { destroy(); }
   private:
      void destroy();
      class SecureQueueNode* head;
      class SecureQueueNode* tail;
   };

}

#endif
