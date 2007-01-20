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
      void write(const byte input[], u32bit length) { send(input, length); }

      Chain(Filter* = 0, Filter* = 0, Filter* = 0, Filter* = 0);
      Chain(Filter*[], u32bit);
   };

/*************************************************
* Fork                                           *
*************************************************/
class Fork : public Fanout_Filter
   {
   public:
      void write(const byte input[], u32bit length) { send(input, length); }
      void set_port(u32bit n) { Fanout_Filter::set_port(n); }

      Fork(Filter*, Filter*, Filter* = 0, Filter* = 0);
      Fork(Filter*[], u32bit);
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

      Keyed_Filter() { base_ptr = 0; }
   protected:
      SymmetricAlgorithm* base_ptr;
   };

}

#endif
