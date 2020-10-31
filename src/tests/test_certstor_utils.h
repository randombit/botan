/*
* (C) 1999-2019 Jack Lloyd
* (C) 2019      René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TEST_CERT_STORE_UTILS_H_
#define BOTAN_TEST_CERT_STORE_UTILS_H_

#include <string>
#include <vector>

#include <botan/build.h>

#if defined(BOTAN_HAS_X509_CERTIFICATES)

#include <botan/pkix_types.h>

namespace Botan_Tests {

Botan::X509_DN read_dn(const std::string hex);

Botan::X509_DN get_dn();

Botan::X509_DN get_utf8_dn();

std::vector<uint8_t> get_key_id();

Botan::X509_DN get_unknown_dn();

Botan::X509_DN get_skewed_dn();

std::vector<uint8_t> get_unknown_key_id();
}

#endif

#endif
