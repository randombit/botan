/*
* Utils for calling BearSSL
* (C) 2015,2016 Jack Lloyd
* (C) 2017 Patrick Wildt
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_INTERNAL_BEARSSL_H_
#define BOTAN_INTERNAL_BEARSSL_H_

#include <botan/pk_ops_fwd.h>
#include <botan/secmem.h>
#include <botan/exceptn.h>
#include <memory>
#include <string>

namespace Botan {

class HashFunction;

class BearSSL_Error final : public Exception
   {
   public:
      BearSSL_Error(const std::string& what) :
         Exception(what + " failed") {}
   };

/* Hash */

std::unique_ptr<HashFunction>
make_bearssl_hash(const std::string& name);

/* ECDSA */

#if defined(BOTAN_HAS_ECDSA)

class ECDSA_PublicKey;
class ECDSA_PrivateKey;

std::unique_ptr<PK_Ops::Verification>
make_bearssl_ecdsa_ver_op(const ECDSA_PublicKey& key, const std::string& params);
std::unique_ptr<PK_Ops::Signature>
make_bearssl_ecdsa_sig_op(const ECDSA_PrivateKey& key, const std::string& params);

#endif

}

#endif
