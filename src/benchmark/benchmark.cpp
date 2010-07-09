/*
* Runtime benchmarking
* (C) 2008-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/benchmark.h>
#include <botan/buf_comp.h>
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <memory>
#include <vector>
#include <chrono>
namespace Botan {

namespace {

typedef std::chrono::high_resolution_clock benchmark_clock;

/**
* Benchmark BufferedComputation (hash or MAC)
*/
std::pair<u64bit, u64bit> bench_buf_comp(BufferedComputation* buf_comp,
                                         u64bit nanoseconds_max,
                                         const byte buf[], u32bit buf_len)
   {
   u64bit reps = 0;

   std::chrono::nanoseconds max_time(nanoseconds_max);
   std::chrono::nanoseconds time_used(0);

   while(time_used < max_time)
      {
      auto start = benchmark_clock::now();
      buf_comp->update(buf, buf_len);
      time_used += benchmark_clock::now() - start;

      ++reps;
      }

   u64bit ns_taken =
      std::chrono::duration_cast<std::chrono::nanoseconds>(time_used).count();

   return std::make_pair(reps * buf_len, ns_taken);
   }

/**
* Benchmark block cipher
*/
std::pair<u64bit, u64bit>
bench_block_cipher(BlockCipher* block_cipher,
                   u64bit nanoseconds_max,
                   byte buf[], u32bit buf_len)
   {
   const u32bit in_blocks = buf_len / block_cipher->BLOCK_SIZE;

   u64bit reps = 0;

   std::chrono::nanoseconds max_time(nanoseconds_max);
   std::chrono::nanoseconds time_used(0);

   block_cipher->set_key(buf, block_cipher->MAXIMUM_KEYLENGTH);

   while(time_used < max_time)
      {
      auto start = benchmark_clock::now();
      block_cipher->encrypt_n(buf, buf, in_blocks);
      time_used += benchmark_clock::now() - start;

      ++reps;
      }

   u64bit ns_taken =
      std::chrono::duration_cast<std::chrono::nanoseconds>(time_used).count();

   return std::make_pair(reps * in_blocks * block_cipher->BLOCK_SIZE,
                         ns_taken);
   }

/**
* Benchmark stream
*/
std::pair<u64bit, u64bit>
bench_stream_cipher(StreamCipher* stream_cipher,
                    u64bit nanoseconds_max,
                    byte buf[], u32bit buf_len)
   {
   u64bit reps = 0;

   stream_cipher->set_key(buf, stream_cipher->MAXIMUM_KEYLENGTH);

   std::chrono::nanoseconds max_time(nanoseconds_max);
   std::chrono::nanoseconds time_used(0);

   while(time_used < max_time)
      {
      auto start = benchmark_clock::now();
      stream_cipher->cipher1(buf, buf_len);
      time_used += benchmark_clock::now() - start;

      ++reps;
      }

   u64bit ns_taken =
      std::chrono::duration_cast<std::chrono::nanoseconds>(time_used).count();

   return std::make_pair(reps * buf_len, ns_taken);
   }

/**
* Benchmark hash
*/
std::pair<u64bit, u64bit>
bench_hash(HashFunction* hash,
           u64bit nanoseconds_max,
           const byte buf[], u32bit buf_len)
   {
   return bench_buf_comp(hash, nanoseconds_max, buf, buf_len);
   }

/**
* Benchmark MAC
*/
std::pair<u64bit, u64bit>
bench_mac(MessageAuthenticationCode* mac,
          u64bit nanoseconds_max,
          const byte buf[], u32bit buf_len)
   {
   mac->set_key(buf, mac->MAXIMUM_KEYLENGTH);
   return bench_buf_comp(mac, nanoseconds_max, buf, buf_len);
   }

}

std::map<std::string, double>
algorithm_benchmark(const std::string& name,
                    u32bit milliseconds,
                    RandomNumberGenerator& rng,
                    Algorithm_Factory& af)
   {
   std::vector<std::string> providers = af.providers_of(name);
   std::map<std::string, double> all_results;

   if(providers.empty()) // no providers, nothing to do
      return all_results;

   const u64bit ns_per_provider =
      (static_cast<u64bit>(milliseconds) * 1000 * 1000) / providers.size();

   std::vector<byte> buf(16 * 1024);
   rng.randomize(&buf[0], buf.size());

   for(u32bit i = 0; i != providers.size(); ++i)
      {
      const std::string provider = providers[i];

      std::pair<u64bit, u64bit> results(0, 0);

      if(const BlockCipher* proto =
            af.prototype_block_cipher(name, provider))
         {
         std::unique_ptr<BlockCipher> block_cipher(proto->clone());
         results = bench_block_cipher(block_cipher.get(),
                                      ns_per_provider,
                                      &buf[0], buf.size());
         }
      else if(const StreamCipher* proto =
                 af.prototype_stream_cipher(name, provider))
         {
         std::unique_ptr<StreamCipher> stream_cipher(proto->clone());
         results = bench_stream_cipher(stream_cipher.get(),
                                       ns_per_provider,
                                       &buf[0], buf.size());
         }
      else if(const HashFunction* proto =
                 af.prototype_hash_function(name, provider))
         {
         std::unique_ptr<HashFunction> hash(proto->clone());
         results = bench_hash(hash.get(), ns_per_provider,
                              &buf[0], buf.size());
         }
      else if(const MessageAuthenticationCode* proto =
                 af.prototype_mac(name, provider))
         {
         std::unique_ptr<MessageAuthenticationCode> mac(proto->clone());
         results = bench_mac(mac.get(), ns_per_provider,
                             &buf[0], buf.size());
         }

      if(results.first && results.second)
         {
         /* 953.67 == 1000 * 1000 * 1000 / 1024 / 1024 - the conversion
            factor from bytes per nanosecond to mebibytes per second.
         */
         double speed = (953.67 * results.first) / results.second;
         all_results[provider] = speed;
         }
      }

   return all_results;
   }

}
