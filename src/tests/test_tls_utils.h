/*
* (C) 1999-2021 Jack Lloyd
* (C) 2021      René Meusel, Hannes Rantzsch
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TEST_TLS_UTILS_H_
#define BOTAN_TEST_TLS_UTILS_H_

#include <string>

#include <botan/build.h>

#if defined(BOTAN_HAS_TLS)

#include <botan/tls_policy.h>

namespace Botan_Tests {

Botan::TLS::Text_Policy read_tls_policy(const std::string &policy_file);

}

#endif

#endif