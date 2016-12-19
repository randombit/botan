/*
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include <botan/symkey.h>

namespace Botan_Tests {

namespace {

using Botan::OctetString;

Test::Result test_from_rng() {
  Test::Result result("OctetString");

  OctetString os(Test::rng(), 32);
  result.test_eq("length is 32 bytes", os.size(), 32);

  return result;
}

Test::Result test_from_hex() {
  Test::Result result("OctetString");

  OctetString os("0123456789ABCDEF");
  result.test_eq("length is 8 bytes", os.size(), 8);

  return result;
}

Test::Result test_from_byte() {
  Test::Result result("OctetString");

  auto rand_bytes = Test::rng().random_vec(8);
  OctetString os(rand_bytes.data(), rand_bytes.size());
  result.test_eq("length is 8 bytes", os.size(), 8);

  return result;
}

Test::Result test_odd_parity() {
  Test::Result result("OctetString");

  OctetString os("FFFFFFFFFFFFFFFF");
  os.set_odd_parity();
  OctetString expected("FEFEFEFEFEFEFEFE");
  result.test_eq("odd parity set correctly", os, expected);

  OctetString os2("EFCBDA4FAA997F63");
  os2.set_odd_parity();
  OctetString expected2("EFCBDA4FAB987F62");
  result.test_eq("odd parity set correctly", os2, expected2);

  return result;
}

Test::Result test_as_string() {
  Test::Result result("OctetString");

  OctetString os("0123456789ABCDEF");
  result.test_eq("OctetString::as_string() returns correct string", os.as_string(), "0123456789ABCDEF");

  return result;
}

Test::Result test_xor() {
  Test::Result result("OctetString");

  OctetString os1("0000000000000000");
  OctetString os2("FFFFFFFFFFFFFFFF");

  OctetString xor_result = os1 ^ os2;
  result.test_eq("OctetString XOR operations works as expected", xor_result, os2);

  xor_result = os1;
  xor_result ^= os2;
  result.test_eq("OctetString XOR operations works as expected", xor_result, os2);

  xor_result = os2 ^ os2;
  result.test_eq("OctetString XOR operations works as expected", xor_result, os1);

  OctetString os3("0123456789ABCDEF");
  xor_result = os3 ^ os2;
  OctetString expected("FEDCBA9876543210");
  result.test_eq("OctetString XOR operations works as expected", xor_result, expected);

  return result;
}

Test::Result test_equality() {
  Test::Result result("OctetString");

  OctetString os1("0000000000000000");
  OctetString os2("FFFFFFFFFFFFFFFF");

  result.confirm("OctetString equality operations works as expected", os1 == os1);
  result.confirm("OctetString equality operations works as expected", os2 == os2);
  result.confirm("OctetString equality operations works as expected", os1 != os2);

  return result;
}

Test::Result test_append() {
  Test::Result result("OctetString");

  OctetString os1("0000");
  OctetString os2("FFFF");
  OctetString expected("0000FFFF");

  OctetString append_result = os1 + os2;

  result.test_eq("OctetString append operations works as expected", append_result, expected);

  return result;
}

class OctetString_Tests : public Test {
public:
  std::vector<Test::Result> run() override {
    std::vector<Test::Result> results;

    std::vector<std::function<Test::Result()>> fns = {
      test_from_rng,
      test_from_hex,
      test_from_byte,
      test_odd_parity,
      test_as_string,
      test_xor,
      test_equality,
      test_append
    };

    for (size_t i = 0; i != fns.size(); ++i) {
      try {
        results.push_back(fns[ i ]());
      }
      catch (std::exception& e) {
        results.push_back(Test::Result::Failure("OctetString tests " + std::to_string(i), e.what()));
      }
    }

    return results;
  }
};

BOTAN_REGISTER_TEST("octetstring", OctetString_Tests);

}

}
