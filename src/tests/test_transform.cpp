#include "tests.h"

#include <botan/botan.h>
#include <botan/transform.h>
#include <botan/threefish.h>
#include <botan/benchmark.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

Transformation* get_transform(const std::string& algo)
   {
   throw std::runtime_error("Unknown transform " + algo);
   }

secure_vector<byte> transform_test(const std::string& algo,
                                   const secure_vector<byte>& nonce,
                                   const secure_vector<byte>& key,
                                   const secure_vector<byte>& in)
   {
   std::unique_ptr<Transformation> transform(get_transform(algo));

   transform->set_key(key);
   transform->start_vec(nonce);

   secure_vector<byte> out = in;
   transform->update(out, 0);

   return out;
   }

}

size_t test_transform()
   {
   std::ifstream vec(TEST_DATA_DIR "/transform.vec");

   return run_tests(vec, "Transform", "Output", true,
             [](std::map<std::string, std::string> m)
             {
             return hex_encode(transform_test(m["Transform"],
                                              hex_decode_locked(m["Nonce"]),
                                              hex_decode_locked(m["Key"]),
                                              hex_decode_locked(m["Input"])));
             });
   }
