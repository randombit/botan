/*
* (C) 2022 Jack Lloyd
* (C) 2022 Hannes Rantzsch, René Meusel - neXenio
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS_13)

#include <botan/internal/tls_transcript_hash_13.h>

using namespace Botan::TLS;

namespace {

using Test = Botan_Tests::Test;

template<typename FunT>
Test::Result CHECK(const char* name, FunT check_fun)
   {
   Botan_Tests::Test::Result r(name);
   try
      {
      check_fun(r);
      }
   catch(const Botan_Tests::Test_Aborted&)
      {
      // pass, failure was already noted in the responsible `require`
      }
   catch(const std::exception& ex)
      {
      r.test_failure(std::string("failed with exception: ") + ex.what());
      }
   return r;
   }

std::vector<Test::Result> transcript_hash()
   {
   auto sha256 = [](const auto& str) {
      return Botan::unlock(Botan::HashFunction::create_or_throw("SHA-256")->process(Botan::hex_decode(str)));
   };

   return
      {
      CHECK("trying to get 'previous' or 'current' with invalid state", [](Test::Result& result)
         {
         result.test_throws<Botan::Invalid_State>("previous throws invalid state exception",
         [] { Transcript_Hash_State().previous(); });

         result.test_throws<Botan::Invalid_State>("current throws invalid state exception",
               [] { Transcript_Hash_State().current(); });
         }),

      CHECK("update without an algorithm", [](Test::Result& result)
         {
         Transcript_Hash_State h;
         result.test_no_throw("update is successful", [&] { h.update({0xba, 0xad, 0xbe, 0xef}); });
         result.test_throws<Botan::Invalid_State>("previous throws invalid state exception",
               [&] { h.previous(); });
         result.test_throws<Botan::Invalid_State>("current throws invalid state exception",
               [&] { h.current(); });
         }),

      CHECK("cannot change algorithm", [](Test::Result& result)
         {
         Transcript_Hash_State h;
         result.test_no_throw("initial set is successful", [&] { h.set_algorithm("SHA-256"); });
         result.test_no_throw("resetting is successful (NOOP)", [&] { h.set_algorithm("SHA-256"); });
         result.test_throws<Botan::Invalid_State>("set_algorithm throws invalid state exception",
               [&] { h.set_algorithm("SHA-384"); });

         Transcript_Hash_State h2("SHA-256");
         result.test_no_throw("resetting is successful (NOOP)", [&] { h2.set_algorithm("SHA-256"); });
         result.test_throws<Botan::Invalid_State>("set_algorithm throws invalid state exception",
               [&] { h2.set_algorithm("SHA-384"); });
         }),

      CHECK("update and result retrieval (algorithm is set)", [&](Test::Result& result)
         {
         Transcript_Hash_State h("SHA-256");

         h.update({0xba, 0xad, 0xbe, 0xef});
         result.test_throws<Botan::Invalid_State>("previous throws invalid state exception",
               [&] { h.previous(); });
         result.test_eq("c = SHA-256(baadbeef)", h.current(), sha256("baadbeef"));

         h.update({0x60, 0x0d, 0xf0, 0x0d});
         result.test_eq("p = SHA-256(baadbeef)", h.previous(), sha256("baadbeef"));
         result.test_eq("c = SHA-256(deadbeef | goodfood)", h.current(), sha256("baadbeef600df00d"));
         }),

      CHECK("update and result retrieval (deferred algorithm specification)", [&](Test::Result& result)
         {
         Transcript_Hash_State h;

         h.update({0xba, 0xad, 0xbe, 0xef});
         h.set_algorithm("SHA-256");

         result.test_throws<Botan::Invalid_State>("previous throws invalid state exception",
               [&] { h.previous(); });
         result.test_eq("c = SHA-256(baadbeef)", h.current(), sha256("baadbeef"));
         }),

      CHECK("update and result retrieval (deferred algorithm specification multiple updates)", [&](Test::Result& result)
         {
         Transcript_Hash_State h;

         h.update({0xba, 0xad, 0xbe, 0xef});
         h.update({0x60, 0x0d, 0xf0, 0x0d});
         h.set_algorithm("SHA-256");

         result.test_throws<Botan::Invalid_State>("previous throws invalid state exception",
               [&] { h.previous(); });
         result.test_eq("c = SHA-256(deadbeef | goodfood)", h.current(), sha256("baadbeef600df00d"));
         }),

      CHECK("cloning creates independent transcript_hash instances", [&](Test::Result& result)
         {
         Transcript_Hash_State h1("SHA-256");

         h1.update({0xba, 0xad, 0xbe, 0xef});
         h1.update({0x60, 0x0d, 0xf0, 0x0d});

         auto h2 = h1.clone();
         result.test_eq("c1 = SHA-256(deadbeef | goodfood)", h1.current(), sha256("baadbeef600df00d"));
         result.test_eq("c2 = SHA-256(deadbeef | goodfood)", h2.current(), sha256("baadbeef600df00d"));

         h1.update({0xca, 0xfe, 0xd0, 0x0d});
         result.test_eq("c1 = SHA-256(deadbeef | goodfood | cafedude)", h1.current(), sha256("baadbeef600df00dcafed00d"));
         result.test_eq("c2 = SHA-256(deadbeef | goodfood)", h2.current(), sha256("baadbeef600df00d"));
         }),
      };
   }

}

namespace Botan_Tests {

BOTAN_REGISTER_TEST_FN("tls", "tls_transcript_hash_13", transcript_hash);

}
#endif
