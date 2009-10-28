/*
* Keyed_Filter
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_KEYED_FILTER_H__
#define BOTAN_KEYED_FILTER_H__

#include <botan/filter.h>
#include <botan/sym_algo.h>

namespace Botan {

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
      virtual void set_key(const SymmetricKey& key) = 0;

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
      virtual bool valid_keylength(u32bit length) const = 0;
   };

}

#endif
