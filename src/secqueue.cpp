/*************************************************
* SecureQueue Source File                        *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/secqueue.h>
#include <algorithm>

namespace Botan {

/*************************************************
* SecureQueueNode                                *
*************************************************/
class SecureQueueNode
   {
   public:
      u32bit write(const byte input[], u32bit length)
         {
         u32bit copied = std::min(length, buffer.size() - end);
         copy_mem(buffer + end, input, copied);
         end += copied;
         return copied;
         }
      u32bit read(byte output[], u32bit length)
         {
         u32bit copied = std::min(length, end - start);
         copy_mem(output, buffer + start, copied);
         start += copied;
         return copied;
         }
      u32bit peek(byte output[], u32bit length, u32bit offset = 0)
         {
         const u32bit left = end - start;
         if(offset >= left) return 0;
         u32bit copied = std::min(length, left - offset);
         copy_mem(output, buffer + start + offset, copied);
         return copied;
         }
      u32bit size() const { return (end - start); }
      SecureQueueNode()  { next = 0; start = end = 0; }
      ~SecureQueueNode() { next = 0; start = end = 0; }
   private:
      friend class SecureQueue;
      SecureQueueNode* next;
      SecureBuffer<byte, DEFAULT_BUFFERSIZE> buffer;
      u32bit start, end;
   };

/*************************************************
* Create a SecureQueue                           *
*************************************************/
SecureQueue::SecureQueue()
   {
   set_next(0, 0);
   head = tail = new SecureQueueNode;
   }

/*************************************************
* Copy a SecureQueue                             *
*************************************************/
SecureQueue::SecureQueue(const SecureQueue& input) :
   Fanout_Filter(), DataSource()
   {
   set_next(0, 0);

   head = tail = new SecureQueueNode;
   SecureQueueNode* temp = input.head;
   while(temp)
      {
      write(temp->buffer + temp->start, temp->end - temp->start);
      temp = temp->next;
      }
   }

/*************************************************
* Destroy this SecureQueue                       *
*************************************************/
void SecureQueue::destroy()
   {
   SecureQueueNode* temp = head;
   while(temp)
      {
      SecureQueueNode* holder = temp->next;
      delete temp;
      temp = holder;
      }
   head = tail = 0;
   }

/*************************************************
* Copy a SecureQueue                             *
*************************************************/
SecureQueue& SecureQueue::operator=(const SecureQueue& input)
   {
   destroy();
   head = tail = new SecureQueueNode;
   SecureQueueNode* temp = input.head;
   while(temp)
      {
      write(temp->buffer + temp->start, temp->end - temp->start);
      temp = temp->next;
      }
   return (*this);
   }

/*************************************************
* Add some bytes to the queue                    *
*************************************************/
void SecureQueue::write(const byte input[], u32bit length)
   {
   if(!head)
      head = tail = new SecureQueueNode;
   while(length)
      {
      const u32bit n = tail->write(input, length);
      input += n;
      length -= n;
      if(length)
         {
         tail->next = new SecureQueueNode;
         tail = tail->next;
         }
      }
   }

/*************************************************
* Read some bytes from the queue                 *
*************************************************/
u32bit SecureQueue::read(byte output[], u32bit length)
   {
   u32bit got = 0;
   while(length && head)
      {
      const u32bit n = head->read(output, length);
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
   return got;
   }

/*************************************************
* Read data, but do not remove it from queue     *
*************************************************/
u32bit SecureQueue::peek(byte output[], u32bit length, u32bit offset) const
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

   u32bit got = 0;
   while(length && current)
      {
      const u32bit n = current->peek(output, length, offset);
      offset = 0;
      output += n;
      got += n;
      length -= n;
      current = current->next;
      }
   return got;
   }

/*************************************************
* Return how many bytes the queue holds          *
*************************************************/
u32bit SecureQueue::size() const
   {
   SecureQueueNode* current = head;
   u32bit count = 0;

   while(current)
      {
      count += current->size();
      current = current->next;
      }
   return count;
   }

/*************************************************
* Test if the queue has any data in it           *
*************************************************/
bool SecureQueue::end_of_data() const
   {
   return (size() == 0);
   }

}
