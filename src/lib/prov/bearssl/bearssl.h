/*
* Utils for calling BearSSL
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_INTERNAL_BEARSSL_H__
#define BOTAN_INTERNAL_BEARSSL_H__

#include <botan/pk_ops_fwd.h>
#include <botan/secmem.h>
#include <botan/exceptn.h>
#include <memory>
#include <string>

namespace Botan {

class HashFunction;

class BearSSL_Error : public Exception
   {
   public:
      BearSSL_Error(const std::string& what) :
         Exception(what + " failed") {}
   };

/* Hash */

std::unique_ptr<HashFunction>
make_bearssl_hash(const std::string& name);

}

#endif
