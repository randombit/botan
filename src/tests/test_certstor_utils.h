/*
* (C) 1999-2019 Jack Lloyd
* (C) 2019      René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TEST_CERT_STORE_UTILS_H_
#define BOTAN_TEST_CERT_STORE_UTILS_H_

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/hex.h>
#include <botan/x509_dn.h>

namespace Botan_Tests {

Botan::X509_DN read_dn(const std::string hex);

Botan::X509_DN get_dn();

std::vector<uint8_t> get_key_id();

Botan::X509_DN get_unknown_dn();

Botan::X509_DN get_skewed_dn();

std::vector<uint8_t> get_unknown_key_id();
}
#endif

