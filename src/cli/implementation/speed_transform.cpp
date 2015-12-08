/*
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "speed.h"

#include <iostream>
#include <iomanip>

#include <botan/cipher_mode.h>
#include <botan/transform.h>

using namespace Botan;

namespace {
void benchmark_transform(std::unique_ptr<Transform> tf,
                         RandomNumberGenerator& rng,
                         const std::chrono::milliseconds runtime)
   {
   for(size_t buf_size : { 16, 64, 256, 1024, 8192 })
      {
      secure_vector<byte> buffer(buf_size);

      std::chrono::nanoseconds time_used(0);

      tf->start(rng.random_vec(tf->default_nonce_length()));

      auto start = std::chrono::high_resolution_clock::now();

      secure_vector<byte> buf(buf_size);
      size_t reps = 0;
      while(time_used < runtime)
         {
         tf->update(buf);
         buf.resize(buf_size);
         ++reps;
         time_used = std::chrono::high_resolution_clock::now() - start;
         }

      const u64bit nsec_used = std::chrono::duration_cast<std::chrono::nanoseconds>(time_used).count();

      const double seconds_used = static_cast<double>(nsec_used) / 1000000000;

      const double Mbps = ((reps / seconds_used) * buf_size) / 1024 / 1024;

      std::cout << tf->name() << " " << std::setprecision(4) << Mbps
                << " MiB / sec with " << buf_size << " byte blocks" << std::endl;
      }
   }
}

bool benchmark_transform(RandomNumberGenerator& rng, const std::string& algo_name,
                         const std::chrono::milliseconds runtime)
   {
   std::unique_ptr<Transform> tf;
   tf.reset(get_cipher_mode(algo_name, ENCRYPTION));
   if(!tf)
      return false;

   if(Keyed_Transform* keyed = dynamic_cast<Keyed_Transform*>(tf.get()))
      keyed->set_key(rng.random_vec(keyed->key_spec().maximum_keylength()));

   benchmark_transform(std::move(tf), rng, runtime);
   return true;
   }
