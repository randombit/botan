/*
* SecureQueue
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SECURE_QUEUE_H__
#define BOTAN_SECURE_QUEUE_H__

#include <botan/data_src.h>
#include <botan/filter.h>

namespace Botan {

/**
* A queue that knows how to zeroize itself
*/
class BOTAN_DLL SecureQueue : public Fanout_Filter, public DataSource
   {
   public:
      std::string name() const { return "Queue"; }

      void write(const byte[], size_t);

      size_t read(byte[], size_t);
      size_t peek(byte[], size_t, size_t = 0) const;

      bool end_of_data() const;
      size_t size() const;
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
