/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include <botan/transform.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

secure_vector<byte> transform_test(const std::string& algo,
                                   const secure_vector<byte>& nonce,
                                   const secure_vector<byte>& key,
                                   const secure_vector<byte>& in)
   {
   std::unique_ptr<Transform> t(get_transform(algo));

   if(Keyed_Transform* keyed = dynamic_cast<Keyed_Transform*>(t.get()))
      keyed->set_key(key);

   secure_vector<byte> out = in;

   t->start(nonce);
   t->finish(out);
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
