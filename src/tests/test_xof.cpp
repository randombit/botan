/*
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_XOF)
   #include <botan/xof.h>
   #include <botan/internal/fmt.h>
   #include <botan/internal/stl_util.h>

   #if defined(BOTAN_HAS_CSHAKE_XOF)
      // This XOF implementation is not exposed via the library's public interface
      // and is therefore not registered in the XOF::create() factory.
      #include <botan/internal/cshake_xof.h>
   #endif

   #if defined(BOTAN_HAS_AES_CRYSTALS_XOF)
      // This XOF implementation is not exposed via the library's public interface
      // and is therefore not registered in the XOF::create() factory.
      #include <botan/internal/aes_crystals_xof.h>
   #endif
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_XOF)

class XOF_Tests final : public Text_Based_Test {
   public:
      XOF_Tests() : Text_Based_Test("xof", "In,Out", "Salt,Key,Name") {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override {
         const std::vector<uint8_t> in = vars.get_req_bin("In");
         const std::vector<uint8_t> expected = vars.get_req_bin("Out");
         const std::vector<uint8_t> salt = vars.get_opt_bin("Salt");
         const std::vector<uint8_t> key = vars.get_opt_bin("Key");

         // used exclusively for cSHAKE
         [[maybe_unused]] const std::vector<uint8_t> name = vars.get_opt_bin("Name");

         Test::Result result(algo);

         const auto providers = [&]() -> std::vector<std::string> {
   #if defined(BOTAN_HAS_CSHAKE_XOF)
            if(algo == "cSHAKE-128" || algo == "cSHAKE-256") {
               return {"base"};
            }
   #endif

   #if defined(BOTAN_HAS_AES_CRYSTALS_XOF)
            if(algo == "CTR-BE(AES-256)") {
               return {"base"};
            }
   #endif
            return provider_filter(Botan::XOF::providers(algo));
         }();

         if(providers.empty()) {
            result.note_missing("XOF " + algo);
            return result;
         }

         for(const auto& provider_ask : providers) {
            auto xof = [&]() -> std::unique_ptr<Botan::XOF> {
   #if defined(BOTAN_HAS_CSHAKE_XOF)
               if(algo == "cSHAKE-128") {
                  return std::make_unique<Botan::cSHAKE_128_XOF>(name);
               }
               if(algo == "cSHAKE-256") {
                  return std::make_unique<Botan::cSHAKE_256_XOF>(name);
               }
   #endif

   #if defined(BOTAN_HAS_AES_CRYSTALS_XOF)
               if(algo == "CTR-BE(AES-256)") {
                  return std::make_unique<Botan::AES_256_CTR_XOF>();
               }
   #endif
               return Botan::XOF::create(algo, provider_ask);
            }();

            if(!xof) {
               result.test_failure(Botan::fmt("XOF {} supported by {} but not found", algo, provider_ask));
               continue;
            }

            const std::string provider(xof->provider());
            result.test_is_nonempty("provider", provider);
            result.test_eq(provider, xof->name(), algo);

            // Some XOFs don't accept input at all. We assume that this stays the same
            // after calling `XOF::clear()`.
            const auto new_accepts_input = xof->accepts_input();

            result.confirm("advertised block size is > 0", xof->block_size() > 0);
            result.test_eq("new object may accept input", xof->accepts_input(), new_accepts_input);

            // input and output in bulk
            xof->start(salt, key);
            xof->update(in);
            result.test_eq("object may accept input before first output", xof->accepts_input(), new_accepts_input);
            result.test_eq("generated output", xof->output_stdvec(expected.size()), expected);
            result.confirm("object does not accept input after first output", !xof->accepts_input());

            // if not necessary, invoking start() should be optional
            if(salt.empty() && key.empty()) {
               xof->clear();
               xof->update(in);
               result.test_eq("generated output (w/o start())", xof->output_stdvec(expected.size()), expected);
            }

            // input again and output bytewise
            xof->clear();
            result.test_eq("object might accept input after clear()", xof->accepts_input(), new_accepts_input);
            xof->start(salt, key);
            xof->update(in);

            std::vector<uint8_t> singlebyte_out(expected.size());
            for(uint8_t& chr : singlebyte_out) {
               chr = xof->output_next_byte();
            }
            result.test_eq("generated singlebyte output", singlebyte_out, expected);

            // input and output blocksize-ish wise
            auto process_as_blocks = [&](const std::string& id, size_t block_size) {
               auto new_xof = xof->new_object();
               result.test_eq(Botan::fmt("reconstructed XOF may accept input ({})", id),
                              new_xof->accepts_input(),
                              new_accepts_input);

               new_xof->start(salt, key);
               std::span<const uint8_t> in_span(in);
               while(!in_span.empty()) {
                  const auto bytes = std::min(block_size, in_span.size());
                  new_xof->update(in_span.first(bytes));
                  in_span = in_span.last(in_span.size() - bytes);
               }
               std::vector<uint8_t> blockwise_out(expected.size());
               std::span<uint8_t> out_span(blockwise_out);
               while(!out_span.empty()) {
                  const auto bytes = std::min(block_size, out_span.size());
                  new_xof->output(out_span.first(bytes));
                  out_span = out_span.last(out_span.size() - bytes);
               }
               result.test_eq(Botan::fmt("generated blockwise output ({})", id), blockwise_out, expected);
            };

            process_as_blocks("-1", xof->block_size() - 1);
            process_as_blocks("+0", xof->block_size());
            process_as_blocks("+1", xof->block_size() + 1);

            // copy state during processing
            try {
               xof->clear();
               xof->start(salt, key);
               xof->update(std::span(in).first(in.size() / 2));
               auto xof2 = xof->copy_state();
               result.test_eq("copied object might still accept input", xof2->accepts_input(), new_accepts_input);
               xof->update(std::span(in).last(in.size() - in.size() / 2));
               xof2->update(std::span(in).last(in.size() - in.size() / 2));
               auto cp_out1 = xof->output_stdvec(expected.size());
               auto cp_out2_1 = xof2->output_stdvec(expected.size() / 2);
               auto xof3 = xof2->copy_state();
               result.confirm("copied object doesn't allow input after reading output", !xof3->accepts_input());
               auto cp_out2_2a = xof2->output_stdvec(expected.size() - expected.size() / 2);
               auto cp_out2_2b = xof3->output_stdvec(expected.size() - expected.size() / 2);
               result.test_eq("output is equal, after state copy", cp_out1, expected);
               result.test_eq("output is equal, after state copy (A)", Botan::concat(cp_out2_1, cp_out2_2a), expected);
               result.test_eq("output is equal, after state copy (B)", Botan::concat(cp_out2_1, cp_out2_2b), expected);
            } catch(const Botan::Not_Implemented&) {
               // pass...
            }
         }

         return result;
      }

      std::vector<Test::Result> run_final_tests() override {
         return {
   #if defined(BOTAN_HAS_CSHAKE_XOF)
            CHECK("cSHAKE without a name",
                  [](Test::Result& result) {
                     std::vector<std::unique_ptr<Botan::XOF>> cshakes;
                     cshakes.push_back(std::make_unique<Botan::cSHAKE_128_XOF>(""));
                     cshakes.push_back(std::make_unique<Botan::cSHAKE_256_XOF>(""));

                     for(auto& cshake : cshakes) {
                        result.confirm("cSHAKE without a name rejects empty salt", !cshake->valid_salt_length(0));
                        result.confirm("cSHAKE without a name requests at least one byte of salt",
                                       cshake->valid_salt_length(1));
                        result.test_throws("cSHAKE without a name throws without salt", [&]() { cshake->start({}); });
                     }
                  }),
   #endif
   #if defined(BOTAN_HAS_AES_CRYSTALS_XOF)
               CHECK("AES-256/CTR XOF failure modes", [](Test::Result& result) {
                  Botan::AES_256_CTR_XOF aes_xof;
                  result.test_throws("AES-256/CTR XOF throws for empty key", [&]() { aes_xof.start({}, {}); });
                  result.test_throws("AES-256/CTR XOF throws for too long key",
                                     [&]() { aes_xof.start({}, std::vector<uint8_t>(33)); });
                  result.test_throws("AES-256/CTR XOF throws for too long IV",
                                     [&]() { aes_xof.start(std::vector<uint8_t>(17), std::vector<uint8_t>(32)); });
               }),
   #endif
         };
      }
};

BOTAN_REGISTER_SERIALIZED_TEST("xof", "extendable_output_functions", XOF_Tests);

#endif

}  // namespace Botan_Tests
