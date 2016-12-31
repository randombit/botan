/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TPM)
  #include <botan/tpm.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_TPM)

class TPM_Tests : public Test
   {
   public:

      static std::string pin_cb(const std::string& )
         {
         return "123456";
         }

      std::vector<Test::Result> run() override
         {
         Test::Result result("TPM");

         std::unique_ptr<Botan::TPM_Context> ctx;

         try
            {
            ctx.reset(new Botan::TPM_Context(pin_cb, nullptr));
            result.test_success("Created TPM context");
            }
         catch(Botan::TPM_Error& e)
            {
            result.test_success("Error conecting to TPM, skipping tests");
            return {result};
            }

         try
            {
            result.test_note("TPM counter is " + std::to_string(ctx->current_counter()));

            Botan::TPM_RNG rng(*ctx);
            Botan::secure_vector<uint8_t> output = rng.random_vec(16);

            result.test_ne("TPM RNG output not all zeros", output, std::vector<uint8_t>(16));

            Botan::TPM_PrivateKey key(*ctx, 1024, nullptr);
            result.test_success("Created TPM RSA key");

            std::vector<uint8_t> blob = key.export_blob();

            // Has to be at least as large as the key
            result.test_gte("Blob size is reasonable", blob.size(), 1024/8);

            std::vector<std::string> registered_keys = Botan::TPM_PrivateKey::registered_keys(*ctx);

            for(auto url : registered_keys)
               result.test_note("TPM registered key " + url);

            // TODO export public key
            // TODO generate a signature, verify it
            // TODO test key registration mechanisms
            }
         catch(Botan::Exception& e)
            {
            result.test_failure("TPM problem", e.what());
            }

         return {result};
         }

   };

BOTAN_REGISTER_TEST("tpm", TPM_Tests);

#endif

}
