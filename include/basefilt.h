/*************************************************
* Basic Filters Header File                      *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_BASEFILT_H__
#define BOTAN_BASEFILT_H__

#include <botan/filter.h>

namespace Botan {

/*************************************************
* Chain                                          *
*************************************************/
class Chain : public Fanout_Filter
   {
   public:
     typedef Filter::SharedFilterPtrConverter SharedFilterPtrConverter;
     typedef Filter::SharedFilterPtr SharedFilterPtr;

   private:
      template<typename ConstIter>
      void init(ConstIter begin, ConstIter end)
         {
         for( ; begin != end; ++begin)
            {
            if(*begin)
               {
               this->attach(*begin);
               this->incr_owns();
               }
            }
         }

   public:
      void write(const byte input[], u32bit length) { send(input, length); }

      Chain(SharedFilterPtrConverter const&,
           SharedFilterPtrConverter const& = SharedFilterPtrConverter(),
           SharedFilterPtrConverter const& = SharedFilterPtrConverter(),
           SharedFilterPtrConverter const& = SharedFilterPtrConverter());

      template<typename ConstIter>
      Chain(ConstIter begin, ConstIter end)
         : Fanout_Filter()
         { 
         this->init(begin, end); 
         }

   };

/*************************************************
* Fork                                           *
*************************************************/
class Fork : public Fanout_Filter
   {
   public:
      void write(const byte input[], u32bit length) { send(input, length); }
      void set_port(u32bit n) { Fanout_Filter::set_port(n); }

      Fork(SharedFilterPtrConverter const& = SharedFilterPtrConverter(),
           SharedFilterPtrConverter const& = SharedFilterPtrConverter(),
           SharedFilterPtrConverter const& = SharedFilterPtrConverter(),
           SharedFilterPtrConverter const& = SharedFilterPtrConverter());
      template<typename ConstIter>
      Fork(ConstIter begin, ConstIter end)
         : Fanout_Filter()
         { 
         this->set_next(begin, end); 
         }

   };

/*************************************************
* Keyed Filter                                   *
*************************************************/
class Keyed_Filter : public Filter
   {
   public:
      virtual void set_key(const SymmetricKey&);
      virtual void set_iv(const InitializationVector&) {}
      virtual bool valid_keylength(u32bit) const;

      Keyed_Filter() : base_ptr() { }
   protected:
	   std::tr1::shared_ptr<SymmetricAlgorithm> base_ptr;
   };

}

#endif
