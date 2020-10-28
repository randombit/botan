/*
* (C) 2014,2015 Jack Lloyd
* (C) 2016 René Korthaus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_MAC)
   #include <botan/mac.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_MAC)

class Message_Auth_Tests final : public Text_Based_Test
   {
   public:
      Message_Auth_Tests() : Text_Based_Test("mac", "Key,In,Out", "IV") {}

      std::vector<std::string> possible_providers(const std::string& algo) override
         {
         return provider_filter(Botan::MessageAuthenticationCode::providers(algo));
         }

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         const std::vector<uint8_t> key      = vars.get_req_bin("Key");
         const std::vector<uint8_t> input    = vars.get_req_bin("In");
         const std::vector<uint8_t> expected = vars.get_req_bin("Out");
         const std::vector<uint8_t> iv       = vars.get_opt_bin("IV");

         Test::Result result(algo);

         const std::vector<std::string> providers = possible_providers(algo);

         if(providers.empty())
            {
            result.note_missing("MAC " + algo);
            return result;
            }

         for(auto const& provider_ask : providers)
            {
            std::unique_ptr<Botan::MessageAuthenticationCode> mac(Botan::MessageAuthenticationCode::create(algo, provider_ask));

            if(!mac)
               {
               result.test_failure("MAC " + algo + " supported by " + provider_ask + " but not found");
               continue;
               }

            const std::string provider(mac->provider());

            result.test_is_nonempty("provider", provider);
            result.test_eq(provider, mac->name(), algo);

            try
               {
               std::vector<uint8_t> buf(128);
               mac->update(buf.data(), buf.size());
               result.test_failure("Was able to MAC without a key being set");
               }
            catch(Botan::Invalid_State&)
               {
               result.test_success("Trying to MAC with no key set fails");
               }

            mac->set_key(key);
            mac->start(iv);

            mac->update(input);

            result.test_eq(provider, "correct mac", mac->final(), expected);

            // Test to make sure clear() resets what we need it to
            mac->set_key(key);
            mac->start(iv);
            mac->update("some discarded input");
            mac->clear();

            // do the same to test verify_mac()
            mac->set_key(key);
            mac->start(iv);
            mac->update(input);

            // Test that clone works and does not affect parent object
            std::unique_ptr<Botan::MessageAuthenticationCode> clone(mac->clone());
            result.confirm("Clone has different pointer", mac.get() != clone.get());
            result.test_eq("Clone has same name", mac->name(), clone->name());
            clone->set_key(key);
            clone->start(iv);
            clone->update(Test::rng().random_vec(32));

            result.test_eq(provider + " verify mac", mac->verify_mac(expected.data(), expected.size()), true);

            if(input.size() > 2)
               {
               mac->set_key(key); // Poly1305 requires the re-key
               mac->start(iv);

               mac->update(input[0]);
               mac->update(&input[1], input.size() - 2);
               mac->update(input[input.size() - 1]);

               result.test_eq(provider, "split mac", mac->final(), expected);

               // do the same to test verify_mac()
               mac->set_key(key);
               mac->start(iv);

               mac->update(input[ 0 ]);
               mac->update(&input[ 1 ], input.size() - 2);
               mac->update(input[ input.size() - 1 ]);

               result.test_eq(provider + " split mac", mac->verify_mac(expected.data(), expected.size()), true);
               }

            mac->clear();

            try
               {
               std::vector<uint8_t> buf(128);
               mac->update(buf.data(), buf.size());
               result.test_failure("Was able to MAC without a key being set");
               }
            catch(Botan::Invalid_State&)
               {
               result.test_success("Trying to MAC with no key set (after clear) fails");
               }

            try
               {
               std::vector<uint8_t> buf(mac->output_length());
               mac->final(buf.data());
               result.test_failure("Was able to MAC without a key being set");
               }
            catch(Botan::Invalid_State&)
               {
               result.test_success("Trying to MAC with no key set (after clear) fails");
               }
            }

         return result;
         }
   };

BOTAN_REGISTER_TEST("mac", "mac", Message_Auth_Tests);

#endif

}

}
