/*
* (C) 2016 Daniel Neus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TESTS_PKCS11_H_
#define BOTAN_TESTS_PKCS11_H_

#include "tests.h"

#if defined(BOTAN_HAS_PKCS11)
   #include <botan/p11.h>
#endif

#include <botan/secmem.h>

#include <string>
#include <vector>
#include <functional>

namespace Botan_Tests {

#if defined(BOTAN_HAS_PKCS11)

// PIN is expected to be set to "123456" prior to running the tests
const std::string PIN = "123456";
const auto PIN_SECVEC = Botan::PKCS11::secure_string(PIN.begin(), PIN.end());

const std::string TEST_PIN = "654321";
const auto TEST_PIN_SECVEC = Botan::PKCS11::secure_string(TEST_PIN.begin(), TEST_PIN.end());

// SO PIN is expected to be set to "12345678" prior to running the tests
const std::string SO_PIN = "12345678";
const auto SO_PIN_SECVEC = Botan::PKCS11::secure_string(SO_PIN.begin(), SO_PIN.end());

const std::string TEST_SO_PIN = "87654321";
const auto TEST_SO_PIN_SECVEC = Botan::PKCS11::secure_string(TEST_SO_PIN.begin(), TEST_SO_PIN.end());

class PKCS11_Test : public Test
   {
   protected:
      static std::vector<Test::Result> run_pkcs11_tests(const std::string& name,
            std::vector<std::function<Test::Result()>>& fns);
   };

#endif
}

#endif
