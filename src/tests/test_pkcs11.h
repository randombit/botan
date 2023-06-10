/*
* (C) 2016 Daniel Neus
* (C) 2019 Michael Boric
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TESTS_PKCS11_H_
#define BOTAN_TESTS_PKCS11_H_

#include "tests.h"

#if defined(BOTAN_HAS_PKCS11)
   #include <botan/p11.h>
#endif

#include <string>
#include <vector>

namespace Botan_Tests {

#if defined(BOTAN_HAS_PKCS11)

   #define STRING_AND_FUNCTION(x) #x, x

// PIN is expected to be set to "123456" prior to running the tests
const std::string PKCS11_USER_PIN = "123456";
// SO PIN is expected to be set to "12345678" prior to running the tests
const std::string PKCS11_SO_PIN = "12345678";

// These are pins that should just not match the above (valid) PINs
const std::string PKCS11_TEST_USER_PIN = "654321";
const std::string PKCS11_TEST_SO_PIN = "87654321";

inline Botan::PKCS11::secure_string to_sec_string(const std::string& str) {
   return Botan::PKCS11::secure_string(str.begin(), str.end());
}

inline Botan::PKCS11::secure_string PIN() {
   return to_sec_string(PKCS11_USER_PIN);
}

inline Botan::PKCS11::secure_string SO_PIN() {
   return to_sec_string(PKCS11_SO_PIN);
}

inline Botan::PKCS11::secure_string TEST_PIN() {
   return to_sec_string(PKCS11_TEST_USER_PIN);
}

inline Botan::PKCS11::secure_string TEST_SO_PIN() {
   return to_sec_string(PKCS11_TEST_SO_PIN);
}

std::vector<Test::Result> run_pkcs11_tests(const std::string& name,
                                           std::vector<std::pair<std::string, std::function<Test::Result()>>>& fns);

#endif
}  // namespace Botan_Tests

#endif
