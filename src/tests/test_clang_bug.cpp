/*
* (C) 2020 Jack Lloyd, René Meusel, Hannes Rantzsch
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

/*
 * This test case ensures that we avoid crashing in PKCS8::load_key due to a bug in Clang 8.
 *
 * A detailed description of the issue can be found here: https://github.com/randombit/botan/issues/2255.
 * In short, Clang 8 performs a double-free on captured objects if an exception is thrown within a lambda. This case can
 * occur when PKCS8::load_key fails to load the key due to a wrong password. The password needs to be long enough to not
 * be small buffer optimized.
 *
 * The Clang bug is tracked here and apparently won't be fixed in Clang 8: https://bugs.llvm.org/show_bug.cgi?id=41810.
 * Other Clang versions seem not to be affected.
 */

#include "tests.h"

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)
   #include <botan/pkcs8.h>
   #include <botan/data_src.h>
#endif // BOTAN_HAS_PUBLIC_KEY_CRYPTO

namespace Botan_Tests {

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)

namespace {

// The key needs to be a PKCS #8 encoded and encrypted private key.
std::string getPrivateKey()
   {
   return
      "-----BEGIN ENCRYPTED PRIVATE KEY-----"
      "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"
      "-----END ENCRYPTED PRIVATE KEY-----";
   }

}  // namespace

class Clang_Bug_41810 final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         Test::Result result("PKCS8::load_key does not crash when compiled with Clang 8");

         auto pem = getPrivateKey();

         Botan::DataSource_Memory ds(reinterpret_cast<const uint8_t*>(pem.data()), pem.size());

         std::string pw = "01234567890123456789"; // sufficiently long, wrong password
         // Note: the correct password for this key is "smallbufferoptimization"

         try
            {
            Botan::PKCS8::load_key(ds, Test::rng(), pw);
            result.test_failure("load_key should have thrown due to wrong password");
            }
         catch(const std::exception&)
            {
            result.test_success("load_key doesn't crash");
            }

         return {result};
         }

   };

BOTAN_REGISTER_TEST("misc", "clang_bug", Clang_Bug_41810);

#endif // BOTAN_HAS_PUBLIC_KEY_CRYPTO

}  // namespace Botan_Tests
