#include "validate.h"
#include "bench.h"

#include <botan/libstate.h>
#include <botan/botan.h>
#include <botan/threefish.h>
#include <botan/benchmark.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

Transformation* get_transform(const std::string& algo)
   {
   if(algo == "Threefish-512")
      return new Threefish_512;

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

void test_transform()
   {
   std::ifstream vec("checks/transform.vec");

   run_tests(vec, "Transform", "Output", true,
             [](std::map<std::string, std::string> m)
             {
             return hex_encode(transform_test(m["Transform"],
                                              hex_decode_locked(m["Nonce"]),
                                              hex_decode_locked(m["Key"]),
                                              hex_decode_locked(m["Input"])));
             });

   //time_transform("Threefish-512");
   }

void time_transform(const std::string& algo)
   {
   std::unique_ptr<Transformation> tf(get_transform(algo));

   AutoSeeded_RNG rng;

   tf->set_key(rng.random_vec(tf->maximum_keylength()));
   tf->start_vec(rng.random_vec(tf->default_nonce_length()));

   for(size_t mult : { 1, 2, 4, 8, 16, 128 })
      {
      const size_t buf_size = mult*tf->update_granularity();

      secure_vector<byte> buffer(buf_size);

      double res = time_op(std::chrono::seconds(1),
                           [&tf,&buffer,buf_size]{
                           tf->update(buffer);
                           buffer.resize(buf_size);
                           });

      const u64bit Mbytes = (res * buf_size) / 1024 / 1024;

      std::cout << Mbytes << " MiB / second in " << buf_size << " byte blocks\n";
      }
   }
