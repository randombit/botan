/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_RFC6979_GENERATOR)
  #include <botan/rfc6979.h>
  #include <botan/hex.h>
#endif

#include <iostream>

namespace {

size_t rfc6979_testcase(const std::string& q_str,
                        const std::string& x_str,
                        const std::string& h_str,
                        const std::string& exp_k_str,
                        const std::string& hash,
                        size_t testcase)
   {
   using namespace Botan;

#if defined(BOTAN_HAS_RFC6979_GENERATOR)

   const BigInt q(q_str);
   const BigInt x(x_str);
   const BigInt h(h_str);
   const BigInt exp_k(exp_k_str);

   const BigInt gen_k = generate_rfc6979_nonce(x, q, h, hash);

   if(gen_k != exp_k)
      {
      std::cout << "RFC 6979 test #" << testcase << " failed; generated k="
                << std::hex << gen_k << "\n";
      return 1;
      }

#endif

   return 0;
   }

}

size_t test_rfc6979()
   {
   using namespace Botan;

   size_t fails = 0;

#if defined(BOTAN_HAS_RFC6979_GENERATOR)

   // From RFC 6979 A.1.1
   fails += rfc6979_testcase("0x4000000000000000000020108A2E0CC0D99F8A5EF",
                             "0x09A4D6792295A7F730FC3F2B49CBC0F62E862272F",
                             "0x01795EDF0D54DB760F156D0DAC04C0322B3A204224",
                             "0x23AF4074C90A02B3FE61D286D5C87F425E6BDD81B",
                             "SHA-256", 1);

   // DSA 1024 bits test #1
   fails += rfc6979_testcase("0x996F967F6C8E388D9E28D01E205FBA957A5698B1",
                             "0x411602CB19A6CCC34494D79D98EF1E7ED5AF25F7",
                             "0x8151325DCDBAE9E0FF95F9F9658432DBEDFDB209",
                             "0x7BDB6B0FF756E1BB5D53583EF979082F9AD5BD5B",
                             "SHA-1", 2);

#endif

   test_report("RFC 6979", 2, fails);

   return fails;
   }
