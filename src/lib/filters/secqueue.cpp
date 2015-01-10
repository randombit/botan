/*
* SecureQueue
* (C) 1999-2007 Jack Lloyd
*     2012 Markus Wanner
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/secqueue.h>
#include <algorithm>

namespace Botan {

/**
* A node in a SecureQueue
*/
class SecureQueueNode
   {
   public:
      SecureQueueNode() : buffer(DEFAULT_BUFFERSIZE)
         { next = nullptr; start = end = 0; }

      ~SecureQueueNode() { next = nullptr; start = end = 0; }

      size_t write(const byte input[], size_t length)
         {
         size_t copied = std::min<size_t>(length, buffer.size() - end);
         copy_mem(&buffer[end], input, copied);
         end += copied;
         return copied;
         }

      size_t read(byte output[], size_t length)
         {
         size_t copied = std::min(length, end - start);
         copy_mem(output, &buffer[start], copied);
         start += copied;
         return copied;
         }

      size_t peek(byte output[], size_t length, size_t offset = 0)
         {
         const size_t left = end - start;
         if(offset >= left) return 0;
         size_t copied = std::min(length, left - offset);
         copy_mem(output, &buffer[start + offset], copied);
         return copied;
         }

      size_t size() const { return (end - start); }
   private:
      friend class SecureQueue;
      SecureQueueNode* next;
      secure_vector<byte> buffer;
      size_t start, end;
   };

/*
* Create a SecureQueue
*/
SecureQueue::SecureQueue()
   {
   bytes_read = 0;
   set_next(nullptr, 0);
   head = tail = new SecureQueueNode;
   }

/*
* Copy a SecureQueue
*/
SecureQueue::SecureQueue(const SecureQueue& input) :
   Fanout_Filter(), DataSource()
   {
   bytes_read = 0;
   set_next(nullptr, 0);

   head = tail = new SecureQueueNode;
   SecureQueueNode* temp = input.head;
   while(temp)
      {
      write(&temp->buffer[temp->start], temp->end - temp->start);
      temp = temp->next;
      }
   }

/*
* Destroy this SecureQueue
*/
void SecureQueue::destroy()
   {
   SecureQueueNode* temp = head;
   while(temp)
      {
      SecureQueueNode* holder = temp->next;
      delete temp;
      temp = holder;
      }
   head = tail = nullptr;
   }

/*
* Copy a SecureQueue
*/
SecureQueue& SecureQueue::operator=(const SecureQueue& input)
   {
   destroy();
   head = tail = new SecureQueueNode;
   SecureQueueNode* temp = input.head;
   while(temp)
      {
      write(&temp->buffer[temp->start], temp->end - temp->start);
      temp = temp->next;
      }
   return (*this);
   }

/*
* Add some bytes to the queue
*/
void SecureQueue::write(const byte input[], size_t length)
   {
   if(!head)
      head = tail = new SecureQueueNode;
   while(length)
      {
      const size_t n = tail->write(input, length);
      input += n;
      length -= n;
      if(length)
         {
         tail->next = new SecureQueueNode;
         tail = tail->next;
         }
      }
   }

/*
* Read some bytes from the queue
*/
size_t SecureQueue::read(byte output[], size_t length)
   {
   size_t got = 0;
   while(length && head)
      {
      const size_t n = head->read(output, length);
      output += n;
      got += n;
      length -= n;
      if(head->size() == 0)
         {
         SecureQueueNode* holder = head->next;
         delete head;
         head = holder;
         }
      }
   bytes_read += got;
   return got;
   }

/*
* Read data, but do not remove it from queue
*/
size_t SecureQueue::peek(byte output[], size_t length, size_t offset) const
   {
   SecureQueueNode* current = head;

   while(offset && current)
      {
      if(offset >= current->size())
         {
         offset -= current->size();
         current = current->next;
         }
      else
         break;
      }

   size_t got = 0;
   while(length && current)
      {
      const size_t n = current->peek(output, length, offset);
      offset = 0;
      output += n;
      got += n;
      length -= n;
      current = current->next;
      }
   return got;
   }

/**
* Return how many bytes have been read so far.
*/
size_t SecureQueue::get_bytes_read() const
   {
   return bytes_read;
   }

/*
* Return how many bytes the queue holds
*/
size_t SecureQueue::size() const
   {
   SecureQueueNode* current = head;
   size_t count = 0;

   while(current)
      {
      count += current->size();
      current = current->next;
      }
   return count;
   }

/*
* Test if the queue has any data in it
*/
bool SecureQueue::end_of_data() const
   {
   return (size() == 0);
   }

bool SecureQueue::empty() const
   {
   return (size() == 0);
   }

}
