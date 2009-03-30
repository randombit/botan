/*
* Basic Filters
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_BASEFILT_H__
#define BOTAN_BASEFILT_H__

#include <botan/filter.h>
#include <botan/sym_algo.h>

namespace Botan {

/**
* This class represents Filter chains. A Filter chain is an ordered
* concatenation of Filters, the input to a Chain sequentially passes
* through all the Filters contained in the Chain.
*/

class BOTAN_DLL Chain : public Fanout_Filter
   {
   public:
      void write(const byte input[], u32bit length) { send(input, length); }

      /**
      * Construct a chain of up to four filters. The filters are set
      * up in the same order as the arguments.
      */
      Chain(Filter* = 0, Filter* = 0, Filter* = 0, Filter* = 0);

      /**
      * Construct a chain from range of filters
      * @param filter_arr the list of filters
      * @param length how many filters
      */
      Chain(Filter* filter_arr[], u32bit length);
   };

/**
* This class represents a fork filter, whose purpose is to fork the
* flow of data. It causes an input message to result in n messages at
* the end of the filter, where n is the number of forks.
*/
class BOTAN_DLL Fork : public Fanout_Filter
   {
   public:
      void write(const byte input[], u32bit length) { send(input, length); }
      void set_port(u32bit n) { Fanout_Filter::set_port(n); }

      /**
      * Construct a Fork filter with up to four forks.
      */
      Fork(Filter*, Filter*, Filter* = 0, Filter* = 0);

      /**
      * Construct a Fork from range of filters
      * @param filter_arr the list of filters
      * @param length how many filters
      */
      Fork(Filter* filter_arr[], u32bit length);
   };

/**
* This class represents keyed filters, i.e. filters that have to be
* fed with a key in order to function.
*/
class BOTAN_DLL Keyed_Filter : public Filter
   {
   public:

      /**
      * Set the key of this filter.
      * @param key the key to set
      */
      virtual void set_key(const SymmetricKey& key);

      /**
      * Set the initialization vector of this filter.
      * @param iv the initialization vector to set
      */
      virtual void set_iv(const InitializationVector&) {}

      /**
      * Check whether a key length is valid for this filter.
      * @param length the key length to be checked for validity
      * @return true if the key length is valid, false otherwise
      */
      virtual bool valid_keylength(u32bit length) const;

      Keyed_Filter() { base_ptr = 0; }
   protected:
      SymmetricAlgorithm* base_ptr;
   };

}

#endif
