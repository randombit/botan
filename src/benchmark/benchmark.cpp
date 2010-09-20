/**
* Runtime benchmarking
* (C) 2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/benchmark.h>
#include <botan/buf_comp.h>
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/util.h>
#include <memory>

namespace Botan {

namespace {

/**
* Benchmark BufferedComputation (hash or MAC)
*/
std::pair<u64bit, u64bit> bench_buf_comp(BufferedComputation* buf_comp,
                                         Timer& timer,
                                         u64bit nanoseconds_max,
                                         const byte buf[], u32bit buf_len)
   {
   const u64bit start = timer.clock();
   u64bit nanoseconds_used = 0;
   u64bit reps = 0;

   while(nanoseconds_used < nanoseconds_max)
      {
      buf_comp->update(buf, buf_len);
      ++reps;
      nanoseconds_used = timer.clock() - start;
      }

   return std::make_pair(reps * buf_len, nanoseconds_used);
   }

/**
* Benchmark block cipher
*/
std::pair<u64bit, u64bit>
bench_block_cipher(BlockCipher* block_cipher,
                   Timer& timer,
                   u64bit nanoseconds_max,
                   byte buf[], u32bit buf_len)
   {
   const u64bit start = timer.clock();
   u64bit nanoseconds_used = 0;
   u64bit reps = 0;

   const u32bit in_blocks = buf_len / block_cipher->BLOCK_SIZE;

   while(nanoseconds_used < nanoseconds_max)
      {
      for(u32bit i = 0; i != in_blocks; ++i)
         block_cipher->encrypt(buf + block_cipher->BLOCK_SIZE * i);

      ++reps;
      nanoseconds_used = timer.clock() - start;
      }

   return std::make_pair(reps * in_blocks * block_cipher->BLOCK_SIZE,
                         nanoseconds_used);
   }

/**
* Benchmark stream
*/
std::pair<u64bit, u64bit>
bench_stream_cipher(StreamCipher* stream_cipher,
                    Timer& timer,
                    u64bit nanoseconds_max,
                    byte buf[], u32bit buf_len)
   {
   const u64bit start = timer.clock();
   u64bit nanoseconds_used = 0;
   u64bit reps = 0;

   while(nanoseconds_used < nanoseconds_max)
      {
      stream_cipher->encrypt(buf, buf_len);
      ++reps;
      nanoseconds_used = timer.clock() - start;
      }

   return std::make_pair(reps * buf_len, nanoseconds_used);
   }

/**
* Benchmark hash
*/
std::pair<u64bit, u64bit>
bench_hash(HashFunction* hash, Timer& timer,
           u64bit nanoseconds_max,
           const byte buf[], u32bit buf_len)
   {
   return bench_buf_comp(hash, timer, nanoseconds_max, buf, buf_len);
   }

/**
* Benchmark MAC
*/
std::pair<u64bit, u64bit>
bench_mac(MessageAuthenticationCode* mac,
          Timer& timer,
          u64bit nanoseconds_max,
          const byte buf[], u32bit buf_len)
   {
   mac->set_key(buf, mac->MAXIMUM_KEYLENGTH);
   return bench_buf_comp(mac, timer, nanoseconds_max, buf, buf_len);
   }

}

std::map<std::string, double>
algorithm_benchmark(const std::string& name,
                    Algorithm_Factory& af,
                    RandomNumberGenerator& rng,
                    u32bit milliseconds,
                    u32bit)
   {
   Default_Benchmark_Timer timer;

   return algorithm_benchmark(name,
                              milliseconds,
                              timer,
                              rng,
                              af);
   }

std::map<std::string, double>
algorithm_benchmark(const std::string& name,
                    u32bit milliseconds,
                    Timer& timer,
                    RandomNumberGenerator& rng,
                    Algorithm_Factory& af)
   {
   std::vector<std::string> providers = af.providers_of(name);
   std::map<std::string, double> all_results;

   if(providers.empty()) // no providers, nothing to do
      return all_results;

   const u64bit ns_per_provider =
      ((u64bit)milliseconds * 1000 * 1000) / providers.size();

   std::vector<byte> buf(16 * 1024);
   rng.randomize(&buf[0], buf.size());

   for(u32bit i = 0; i != providers.size(); ++i)
      {
      const std::string provider = providers[i];

      std::pair<u64bit, u64bit> results(0, 0);

      if(const BlockCipher* proto =
            af.prototype_block_cipher(name, provider))
         {
         std::auto_ptr<BlockCipher> block_cipher(proto->clone());
         results = bench_block_cipher(block_cipher.get(), timer,
                                      ns_per_provider,
                                      &buf[0], buf.size());
         }
      else if(const StreamCipher* proto =
                 af.prototype_stream_cipher(name, provider))
         {
         std::auto_ptr<StreamCipher> stream_cipher(proto->clone());
         results = bench_stream_cipher(stream_cipher.get(), timer,
                                       ns_per_provider,
                                       &buf[0], buf.size());
         }
      else if(const HashFunction* proto =
                 af.prototype_hash_function(name, provider))
         {
         std::auto_ptr<HashFunction> hash(proto->clone());
         results = bench_hash(hash.get(), timer, ns_per_provider,
                              &buf[0], buf.size());
         }
      else if(const MessageAuthenticationCode* proto =
                 af.prototype_mac(name, provider))
         {
         std::auto_ptr<MessageAuthenticationCode> mac(proto->clone());
         results = bench_mac(mac.get(), timer, ns_per_provider,
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
