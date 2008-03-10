/*************************************************
* Filter Header File                             *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_FILTER_H__
#define BOTAN_FILTER_H__

#include <botan/base.h>
#include <vector>

namespace Botan {

/*************************************************
* Filter Base Class                              *
*************************************************/
class Filter
   {
   public:
      virtual void write(const byte[], u32bit) = 0;
      virtual void start_msg() {}
      virtual void end_msg() {}
      virtual bool attachable() { return true; }
      void new_msg();
      void finish_msg();
      virtual ~Filter() {}
   protected:
      void send(const byte[], u32bit);
      void send(byte input) { send(&input, 1); }
      void send(const MemoryRegion<byte>& in) { send(in.begin(), in.size()); }
      Filter();
   private:
      Filter(const Filter&) {}
      Filter& operator=(const Filter&) { return (*this); }

      friend class Pipe;
      friend class Fanout_Filter;

      u32bit total_ports() const;
      u32bit current_port() const { return port_num; }
      void set_port(u32bit);

      u32bit owns() const { return filter_owns; }

      void attach(Filter*);
      void set_next(Filter*[], u32bit);
      Filter* get_next() const;

      SecureVector<byte> write_queue;
      std::vector<Filter*> next;
      u32bit port_num, filter_owns;
      bool owned;
   };

/*************************************************
* Fanout Filter Base Class                       *
*************************************************/
class Fanout_Filter : public Filter
   {
   protected:
      void incr_owns() { ++filter_owns; }

      void set_port(u32bit n) { Filter::set_port(n); }
      void set_next(Filter* f[], u32bit n) { Filter::set_next(f, n); }
      void attach(Filter* f) { Filter::attach(f); }
   };

}

#endif
