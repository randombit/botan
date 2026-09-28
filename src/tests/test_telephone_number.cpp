/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TELEPHONE_NUMBER)
   #include <botan/telephone_number.h>
   #include <limits>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_TELEPHONE_NUMBER)

namespace {

class TelephoneNumber_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override { return {test_number(), test_range()}; }

   private:
      static Test::Result test_number() {
         Test::Result result("TelephoneNumber");
         using Botan::TelephoneNumber;

         for(const std::string valid : {"1", "0", "123456789012345", "*67#", "#", "0000"}) {
            const auto tn = TelephoneNumber::from_string(valid);
            if(result.test_is_true("accepts " + valid, tn.has_value())) {
               result.test_str_eq("to_string " + valid, tn->to_string(), valid);
               result.test_sz_eq("length " + valid, tn->length(), valid.size());
            }
         }

         for(const std::string invalid : {"", "1234567890123456", "555-1234", "+15551234", "12 34", "abc", "1\x80"}) {
            result.test_is_false("rejects '" + invalid + "'", TelephoneNumber::from_string(invalid).has_value());
         }

         const auto plain = TelephoneNumber::from_string("0123").value();
         result.test_is_false("0123 is not a wildcard", plain.is_wildcard());
         result.test_is_true("0123 numeric value", plain.numeric_value() == 123);
         result.test_sz_eq("0123 keeps its leading zero", plain.length(), 4);

         const auto wild = TelephoneNumber::from_string("*67#").value();
         result.test_is_true("*67# is a wildcard", wild.is_wildcard());
         result.test_is_false("*67# has no numeric value", wild.numeric_value().has_value());

         result.test_is_true("equality", plain == TelephoneNumber::from_string("0123").value());
         result.test_is_true("0123 and 123 differ", plain != TelephoneNumber::from_string("123").value());
         result.test_is_true("ordering is by string form",
                             TelephoneNumber::from_string("10").value() < TelephoneNumber::from_string("9").value());

         return result;
      }

      static Test::Result test_range() {
         Test::Result result("TelephoneNumberRange");
         using Botan::TelephoneNumber;
         using Botan::TelephoneNumberRange;

         const auto tn = [](std::string_view s) { return TelephoneNumber::from_string(s).value(); };

         result.test_is_false("wildcard start rejected", TelephoneNumberRange::from(tn("12#"), 5).has_value());
         result.test_is_false("zero count rejected", TelephoneNumberRange::from(tn("111"), 0).has_value());
         result.test_is_false("one count rejected", TelephoneNumberRange::from(tn("111"), 1).has_value());
         result.test_is_false("10 + 91 rejected", TelephoneNumberRange::from(tn("10"), 91).has_value());
         result.test_is_true("10 + 90 accepted", TelephoneNumberRange::from(tn("10"), 90).has_value());
         result.test_is_true("998 + 2 accepted", TelephoneNumberRange::from(tn("998"), 2).has_value());
         result.test_is_false("999 + 2 rejected", TelephoneNumberRange::from(tn("999"), 2).has_value());
         result.test_is_true("15 digit full span accepted",
                             TelephoneNumberRange::from(tn("100000000000000"), 900000000000000).has_value());
         result.test_is_false("15 digit overflow rejected",
                              TelephoneNumberRange::from(tn("100000000000000"), 900000000000001).has_value());
         result.test_is_false("huge count rejected",
                              TelephoneNumberRange::from(tn("1"), std::numeric_limits<uint64_t>::max()).has_value());

         const auto range = TelephoneNumberRange::from(tn("0550100"), 10).value();
         result.test_str_eq("start", range.start().to_string(), "0550100");
         result.test_is_true("count", range.count() == 10);
         result.test_str_eq("last keeps the leading zero", range.last().to_string(), "0550109");
         result.test_is_true("contains start", range.contains(tn("0550100")));
         result.test_is_true("contains last", range.contains(tn("0550109")));
         result.test_is_false("excludes the next number", range.contains(tn("0550110")));
         result.test_is_false("excludes the previous number", range.contains(tn("0550099")));
         result.test_is_false("excludes a shorter number of the same value", range.contains(tn("550105")));
         result.test_is_false("excludes a wildcard", range.contains(tn("055010#")));

         result.test_is_true("contains itself", range.contains(range));
         result.test_is_true("contains a sub range",
                             range.contains(TelephoneNumberRange::from(tn("0550102"), 3).value()));
         result.test_is_false("excludes a spilling range",
                              range.contains(TelephoneNumberRange::from(tn("0550105"), 6).value()));
         result.test_is_false("excludes a range of another length",
                              range.contains(TelephoneNumberRange::from(tn("550100"), 2).value()));

         const auto all_nines = TelephoneNumberRange::from(tn("9990000"), 10000).value();
         result.test_str_eq("last of a block ending in nines", all_nines.last().to_string(), "9999999");

         return result;
      }
};

BOTAN_REGISTER_TEST("utils", "telephone_number", TelephoneNumber_Tests);

}  // namespace

#endif

}  // namespace Botan_Tests
