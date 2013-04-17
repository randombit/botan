/*
* Runtime benchmarking
* (C) 2008-2009,2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/benchmark.h>
#include <botan/buf_comp.h>
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/aead.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <memory>
#include <vector>
#include <chrono>

namespace Botan {

namespace {

double time_op(std::chrono::nanoseconds runtime, std::function<void ()> op)
   {
   std::chrono::nanoseconds time_used(0);
   size_t reps = 0;

   auto start = std::chrono::high_resolution_clock::now();

   while(time_used < runtime)
      {
      op();
      ++reps;
      time_used = std::chrono::high_resolution_clock::now() - start;
      }

   const u64bit nsec_used = std::chrono::duration_cast<std::chrono::nanoseconds>(time_used).count();

   const double seconds_used = static_cast<double>(nsec_used) / 1000000000;

   return reps / seconds_used; // ie, return ops per second
   }

}

std::map<std::string, double>
time_algorithm_ops(const std::string& name,
                   Algorithm_Factory& af,
                   const std::string& provider,
                   RandomNumberGenerator& rng,
                   std::chrono::nanoseconds runtime,
                   size_t buf_size)
   {
   const size_t Mebibyte = 1024*1024;

   secure_vector<byte> buffer(buf_size * 1024);
   rng.randomize(&buffer[0], buffer.size());

   const double mb_mult = buffer.size() / static_cast<double>(Mebibyte);

   if(const BlockCipher* proto = af.prototype_block_cipher(name, provider))
      {
      std::unique_ptr<BlockCipher> bc(proto->clone());

      const SymmetricKey key(rng, bc->maximum_keylength());

      return std::map<std::string, double>({
            { "key schedule", time_op(runtime / 8, [&]() { bc->set_key(key); }) },
            { "encrypt", mb_mult * time_op(runtime / 2, [&]() { bc->encrypt(buffer); }) },
            { "decrypt", mb_mult * time_op(runtime / 2, [&]() { bc->decrypt(buffer); }) },
         });
      }
   else if(const StreamCipher* proto = af.prototype_stream_cipher(name, provider))
      {
      std::unique_ptr<StreamCipher> sc(proto->clone());

      const SymmetricKey key(rng, sc->maximum_keylength());

      return std::map<std::string, double>({
            { "key schedule", time_op(runtime / 8, [&]() { sc->set_key(key); }) },
            { "", mb_mult * time_op(runtime, [&]() { sc->encipher(buffer); }) },
         });
      }
   else if(const HashFunction* proto = af.prototype_hash_function(name, provider))
      {
      std::unique_ptr<HashFunction> h(proto->clone());

      return std::map<std::string, double>({
            { "", mb_mult * time_op(runtime, [&]() { h->update(buffer); }) },
         });
      }
   else if(const MessageAuthenticationCode* proto = af.prototype_mac(name, provider))
      {
      std::unique_ptr<MessageAuthenticationCode> mac(proto->clone());

      const SymmetricKey key(rng, mac->maximum_keylength());

      return std::map<std::string, double>({
            { "key schedule", time_op(runtime / 8, [&]() { mac->set_key(key); }) },
            { "", mb_mult * time_op(runtime, [&]() { mac->update(buffer); }) },
         });
      }
   else
      {
      std::unique_ptr<AEAD_Mode> enc(get_aead(name, ENCRYPTION));
      std::unique_ptr<AEAD_Mode> dec(get_aead(name, DECRYPTION));

      if(enc && dec)
         {
         const SymmetricKey key(rng, enc->maximum_keylength());

         return std::map<std::string, double>({
               { "key schedule", time_op(runtime / 4, [&]() { enc->set_key(key); dec->set_key(key); }) / 2 },
               { "encrypt", mb_mult * time_op(runtime / 2, [&]() { enc->update(buffer, 0); buffer.resize(buf_size*1024); }) },
               { "decrypt", mb_mult * time_op(runtime / 2, [&]() { dec->update(buffer, 0); buffer.resize(buf_size*1024); }) },
            });
         }
      }

   return std::map<std::string, double>();
   }

namespace {

double find_first_in(const std::map<std::string, double>& m,
                     const std::vector<std::string>& keys)
   {
   for(auto key : keys)
      {
      auto i = m.find(key);
      if(i != m.end())
         return i->second;
      }

   throw std::runtime_error("algorithm_factory no usable keys found in result");
   }

}

std::map<std::string, double>
algorithm_benchmark(const std::string& name,
                    Algorithm_Factory& af,
                    RandomNumberGenerator& rng,
                    std::chrono::milliseconds milliseconds,
                    size_t buf_size)
   {
   const std::vector<std::string> providers = af.providers_of(name);
   const std::chrono::nanoseconds ns_per_provider = milliseconds / providers.size();

   std::map<std::string, double> all_results; // provider -> ops/sec

   for(auto provider : providers)
      {
      auto results = time_algorithm_ops(name, af, provider, rng, ns_per_provider, buf_size);
      all_results[provider] = find_first_in(results, { "", "update", "encrypt" });
      }

   return all_results;
   }

}
