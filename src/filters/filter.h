/*
* Filter
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_FILTER_H__
#define BOTAN_FILTER_H__

#include <botan/secmem.h>
#include <vector>

namespace Botan {

/**
* This class represents general abstract filter objects.
*/
class BOTAN_DLL Filter
   {
   public:

      /**
      * Write a portion of a message to this filter.
      * @param input the input as a byte array
      * @param length the length of the byte array input
      */
      virtual void write(const byte input[], u32bit length) = 0;

      /**
      * Start a new message. Must be closed by end_msg() before another
      * message can be startet.
      */
      virtual void start_msg() {}

      /**
      * Tell the Filter that the current message shall be ended.
      */
      virtual void end_msg() {}

      /**
      * Check whether this filter is an attachable filter.
      * @return true if this filter is attachable, false otherwise
      */
      virtual bool attachable() { return true; }

      /**
      * Start a new message in *this and all following filters. Only for
      * internal use, not intended for use in client applications.
      */
      void new_msg();

      /**
      * End a new message in *this and all following filters. Only for
      * internal use, not intended for use in client applications.
      */
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

      // true if filter belongs to a pipe --> prohibit filter sharing!
      bool owned;
   };

/**
* This is the abstract Fanout_Filter base class.
**/
class BOTAN_DLL Fanout_Filter : public Filter
   {
   protected:
      void incr_owns() { ++filter_owns; }

      void set_port(u32bit n) { Filter::set_port(n); }
      void set_next(Filter* f[], u32bit n) { Filter::set_next(f, n); }
      void attach(Filter* f) { Filter::attach(f); }
   };

/**
* The type of checking to be performed by decoders:
* NONE - no checks, IGNORE_WS - perform checks, but ignore
* whitespaces, FULL_CHECK - perform checks, also complain
* about white spaces.
*/
enum Decoder_Checking { NONE, IGNORE_WS, FULL_CHECK };

}

#endif
