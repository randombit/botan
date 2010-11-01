/*
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
#include <botan/time.h>
#include <memory>

namespace Botan {

namespace {

/**
* Benchmark Buffered_Computation (hash or MAC)
*/
std::pair<u64bit, u64bit> bench_buf_comp(Buffered_Computation* buf_comp,
                                         u64bit nanoseconds_max,
                                         const byte buf[], size_t buf_len)
   {
   u64bit reps = 0;
   u64bit nanoseconds_used = 0;

   while(nanoseconds_used < nanoseconds_max)
      {
      const u64bit start = get_nanoseconds_clock();
      buf_comp->update(buf, buf_len);
      nanoseconds_used += get_nanoseconds_clock() - start;

      ++reps;
      }

   return std::make_pair(reps * buf_len, nanoseconds_used);
   }

/**
* Benchmark block cipher
*/
std::pair<u64bit, u64bit>
bench_block_cipher(BlockCipher* block_cipher,
                   u64bit nanoseconds_max,
                   byte buf[], size_t buf_len)
   {
   const size_t in_blocks = buf_len / block_cipher->block_size();

   u64bit reps = 0;
   u64bit nanoseconds_used = 0;

   block_cipher->set_key(buf, block_cipher->maximum_keylength());

   while(nanoseconds_used < nanoseconds_max)
      {
      const u64bit start = get_nanoseconds_clock();
      block_cipher->encrypt_n(buf, buf, in_blocks);
      nanoseconds_used += get_nanoseconds_clock() - start;

      ++reps;
      }

   return std::make_pair(reps * in_blocks * block_cipher->block_size(),
                         nanoseconds_used);
   }

/**
* Benchmark stream
*/
std::pair<u64bit, u64bit>
bench_stream_cipher(StreamCipher* stream_cipher,
                    u64bit nanoseconds_max,
                    byte buf[], size_t buf_len)
   {
   u64bit reps = 0;
   u64bit nanoseconds_used = 0;

   stream_cipher->set_key(buf, stream_cipher->maximum_keylength());

   while(nanoseconds_used < nanoseconds_max)
      {
      const u64bit start = get_nanoseconds_clock();
      stream_cipher->cipher1(buf, buf_len);
      nanoseconds_used += get_nanoseconds_clock() - start;

      ++reps;
      }

   return std::make_pair(reps * buf_len, nanoseconds_used);
   }

/**
* Benchmark hash
*/
std::pair<u64bit, u64bit>
bench_hash(HashFunction* hash,
           u64bit nanoseconds_max,
           const byte buf[], size_t buf_len)
   {
   return bench_buf_comp(hash, nanoseconds_max, buf, buf_len);
   }

/**
* Benchmark MAC
*/
std::pair<u64bit, u64bit>
bench_mac(MessageAuthenticationCode* mac,
          u64bit nanoseconds_max,
          const byte buf[], size_t buf_len)
   {
   mac->set_key(buf, mac->maximum_keylength());
   return bench_buf_comp(mac, nanoseconds_max, buf, buf_len);
   }

}

std::map<std::string, double>
algorithm_benchmark(const std::string& name,
                    Algorithm_Factory& af,
                    RandomNumberGenerator& rng,
                    u32bit milliseconds,
                    size_t buf_size)
   {
   std::vector<std::string> providers = af.providers_of(name);
   std::map<std::string, double> all_results;

   if(providers.empty()) // no providers, nothing to do
      return all_results;

   const u64bit ns_per_provider =
      (static_cast<u64bit>(milliseconds) * 1000 * 1000) / providers.size();

   std::vector<byte> buf(buf_size * 1024);
   rng.randomize(&buf[0], buf.size());

   for(size_t i = 0; i != providers.size(); ++i)
      {
      const std::string provider = providers[i];

      std::pair<u64bit, u64bit> results(0, 0);

      if(const BlockCipher* proto =
            af.prototype_block_cipher(name, provider))
         {
         std::auto_ptr<BlockCipher> block_cipher(proto->clone());
         results = bench_block_cipher(block_cipher.get(),
                                      ns_per_provider,
                                      &buf[0], buf.size());
         }
      else if(const StreamCipher* proto =
                 af.prototype_stream_cipher(name, provider))
         {
         std::auto_ptr<StreamCipher> stream_cipher(proto->clone());
         results = bench_stream_cipher(stream_cipher.get(),
                                       ns_per_provider,
                                       &buf[0], buf.size());
         }
      else if(const HashFunction* proto =
                 af.prototype_hash_function(name, provider))
         {
         std::auto_ptr<HashFunction> hash(proto->clone());
         results = bench_hash(hash.get(), ns_per_provider,
                              &buf[0], buf.size());
         }
      else if(const MessageAuthenticationCode* proto =
                 af.prototype_mac(name, provider))
         {
         std::auto_ptr<MessageAuthenticationCode> mac(proto->clone());
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
