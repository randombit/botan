/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_AF_ALG_HASH_H_
#define BOTAN_AF_ALG_HASH_H_

#include <memory>
#include <string>

namespace Botan {

class HashFunction;

std::unique_ptr<HashFunction> create_af_alg_hash(const std::string& name);

}

#endif
