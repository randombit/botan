/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_ENTROPY_SOURCE)
   #include <botan/entropy_src.h>
   #include <botan/hex.h>
   #include <botan/rng.h>
#endif

#if defined(BOTAN_HAS_COMPRESSION)
   #include <botan/compression.h>
#endif

namespace Botan_CLI {

#if defined(BOTAN_HAS_ENTROPY_SOURCE)

namespace {

class SeedCapturing_RNG final : public Botan::RandomNumberGenerator {
   public:
      bool accepts_input() const override { return true; }

      void clear() override {}

      bool is_seeded() const override { return false; }

      std::string name() const override { return "SeedCapturing"; }

      size_t samples() const { return m_samples; }

      const std::vector<uint8_t>& seed_material() const { return m_seed; }

   private:
      void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> input) override {
         if(!output.empty()) {
            throw CLI_Error("SeedCapturing_RNG has no output");
         }

         m_samples++;
         m_seed.insert(m_seed.end(), input.begin(), input.end());
      }

   private:
      std::vector<uint8_t> m_seed;
      size_t m_samples = 0;
};

}  // namespace

class Entropy final : public Command {
   public:
      Entropy() : Command("entropy --truncate-at=128 source") {}

      std::string group() const override { return "misc"; }

      std::string description() const override { return "Sample a raw entropy source"; }

      void go() override {
         const std::string req_source = get_arg("source");
         const size_t truncate_sample = get_arg_sz("truncate-at");

         auto& entropy_sources = Botan::Entropy_Sources::global_sources();

         std::vector<std::string> sources;
         if(req_source == "all") {
            sources = entropy_sources.enabled_sources();
         } else {
            sources.push_back(req_source);
         }

         for(const std::string& source : sources) {
            SeedCapturing_RNG rng;
            const size_t entropy_estimate = entropy_sources.poll_just(rng, source);

            if(rng.samples() == 0) {
               output() << "Source " << source << " is unavailable\n";
               continue;
            }

            const auto& sample = rng.seed_material();

            output() << "Polling " << source << " gathered " << sample.size() << " bytes in " << rng.samples()
                     << " outputs with estimated entropy " << entropy_estimate << "\n";

   #if defined(BOTAN_HAS_COMPRESSION)
            if(!sample.empty()) {
               auto comp = Botan::Compression_Algorithm::create("zlib");
               if(comp) {
                  try {
                     Botan::secure_vector<uint8_t> compressed;
                     compressed.assign(sample.begin(), sample.end());
                     comp->start(9);
                     comp->finish(compressed);

                     if(compressed.size() < sample.size()) {
                        output() << "Sample from " << source << " was zlib compressed from " << sample.size()
                                 << " bytes to " << compressed.size() << " bytes\n";
                     }
                  } catch(std::exception& e) {
                     error_output() << "Error while attempting to compress: " << e.what() << "\n";
                  }
               }
            }
   #endif

            if(sample.size() <= truncate_sample) {
               output() << Botan::hex_encode(sample) << "\n";
            } else if(truncate_sample > 0) {
               output() << Botan::hex_encode(sample.data(), truncate_sample) << "...\n";
            }
         }
      }
};

BOTAN_REGISTER_COMMAND("entropy", Entropy);

#endif

}  // namespace Botan_CLI
