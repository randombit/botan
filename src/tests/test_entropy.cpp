/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <botan/entropy_src.h>

#if defined(BOTAN_HAS_COMPRESSION)
  #include <botan/compression.h>
#endif

namespace Botan_Tests {

namespace {

class Entropy_Source_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         static const size_t MAX_ENTROPY = 512;
         static const size_t MAX_SAMPLES = 256;
         static const size_t MAX_ENTROPY_BYTES = 256*1024;

         Botan::Entropy_Sources& srcs = Botan::Entropy_Sources::global_sources();

         std::vector<std::string> src_names = srcs.enabled_sources();

         std::vector<Test::Result> results;

         for(auto&& src_name : src_names)
            {
            Test::Result result("Entropy source " + src_name);

            result.start_timer();

            std::vector<uint8_t> entropy;
            size_t samples = 0;
            size_t entropy_estimate = 0;

            // TODO: add a timeout

            Botan::Entropy_Accumulator accum([&](const uint8_t buf[], size_t buf_len, size_t buf_entropy) -> bool
               {
                  entropy.insert(entropy.end(), buf, buf + buf_len);
                  entropy_estimate += buf_entropy;
                  ++samples;

                  result.test_note("sample " + std::to_string(samples) + " " +
                                   Botan::hex_encode(buf, buf_len) + " " + std::to_string(buf_entropy));

                  result.test_gte("impossible entropy", buf_len * 8, buf_entropy);

                  return (entropy_estimate > MAX_ENTROPY ||
                          samples > MAX_SAMPLES ||
                          entropy.size() > MAX_ENTROPY_BYTES);
               });

            result.confirm("polled source", srcs.poll_just(accum, src_name));

            result.test_note("saw " + std::to_string(samples) +
                             " samples with total estimated entropy " +
                             std::to_string(entropy_estimate));

            //result.test_gte("impossible entropy", entropy.size() * 8, entropy_estimate);

            if(!entropy.empty())
               {
#if defined(BOTAN_HAS_COMPRESSION)
               for(auto comp_algo : { "zlib", "bzip2", "lzma" })
                  {
                  std::unique_ptr<Botan::Compressor_Transform> comp(Botan::make_compressor(comp_algo, 9));

                  if(comp)
                     {
                     Botan::secure_vector<byte> compressed;
                     compressed.assign(entropy.begin(), entropy.end());

                     comp->start();
                     comp->finish(compressed);

                     result.test_gte("compressed entropy better than advertised",
                                     compressed.size() * 8, entropy_estimate);

                     // TODO: perform 2nd poll and check compression differential
                     }

                  }
#endif
               }

            result.end_timer();

            results.push_back(result);
            }

         return results;
         }
   };

BOTAN_REGISTER_TEST("entropy", Entropy_Source_Tests);

}

}
