// -*- mode: C++ -*-
/*************************************************
* Filter Header File                             *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_FILTER_H__
#define BOTAN_FILTER_H__

#include <botan/base.h>
#include <botan/freestore.h>
#include <vector>
#include <iterator>
#include <botan/pointers.h>

namespace Botan {

/*************************************************
* Filter Base Class                              *
*************************************************/
class Filter : public Freestore
   {
   public:
      typedef SharedPtrConverter<Filter> SharedFilterPtrConverter;

      typedef std::auto_ptr<Filter> AutoFilterPtr;
      typedef std::tr1::shared_ptr<Filter> SharedFilterPtr;
      typedef std::vector<SharedFilterPtr> SharedFilterPtrVector;

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
      // CL: The implementation of the compiler generated copy constructor and
      // assignment operator would be fine, but we need(?) them to be private.
      // So we have to provide the default implementation ourselves.
      //
      // TODO: Check if the copy constructor and assignment operator are
      // called at all. Otherwise it would be more idiomatic to declare them
      // without a definition.
      Filter(Filter const& f) : Freestore(f) {}
      Filter& operator=(Filter const& f) 
         {
         Freestore::operator=(f);
         return (*this); 
         }

      friend class Pipe;
      friend class Fanout_Filter;

      u32bit total_ports() const;
      u32bit current_port() const { return port_num; }
      void set_port(u32bit);

      u32bit owns() const { return filter_owns; }

      void attach(SharedFilterPtrConverter const&);

      template<typename FilterPtr>
      class EvaluatesTrue
         {
         public:
            bool operator()(FilterPtr const& p)
               {
                 return p.get() != 0;
               }
         }; 

      // Set the next filters.
      // Assumes that [begin, end) is a range of SharedFilterPtr objects
      // or AutoFilterPtr objects.
      // ConstIter has to be a bidirectional iterator type.
      template<typename ConstIter>
      void set_next(ConstIter begin, ConstIter end)
      {
        typedef std::reverse_iterator<ConstIter> ConstRevIter;
        typedef typename std::iterator_traits<ConstIter>::value_type PtrType;

        // find last element that really contains a pointer
        ConstIter iter = std::find_if(ConstRevIter(end),
                                      ConstRevIter(begin),
                                      EvaluatesTrue<PtrType>()).base();

        this->next.clear();
        this->next.reserve(std::distance(begin, iter));
        for(; begin != iter; ++begin)
           {
             this->next.push_back(SharedFilterPtr(*begin));
           }

        this->port_num = 0;
        this->filter_owns = 0;
      }

     // The followig overloads are replacements
     // for set_next(Filter* v[], u32bit size).
     // I'd rather forego them completely, above range based
     // function template overload is much more idiomatic.
//      void set_next(SharedFilterPtr const v[], u32bit size) 
//         {
//         this->set_next<SharedFilterPtr const*>(v, v + size); 
//         }
//
//      void set_next(AutoFilterPtr v[], u32bit size) 
//         {
//         this->set_next<AutoFilterPtr*>(v, v + size); 
//         }

      SharedFilterPtr const get_next() const;

      SecureVector<byte> write_queue;
      SharedFilterPtrVector next;
      u32bit port_num, filter_owns;
      bool owned; // true if filter belongs to a pipe --> prohibit filter sharing!
   };

/*************************************************
* Fanout Filter Base Class                       *
*************************************************/
class Fanout_Filter : public Filter
   {
   protected:
      void incr_owns() { ++filter_owns; }

      using Filter::set_port;
      using Filter::set_next;
      using Filter::attach;
   };

}

#endif
