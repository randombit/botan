/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_engine.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/internal/fmt.h>
#include <algorithm>

#if defined(BOTAN_HAS_THREAD_UTILS)
   #include <botan/internal/thread_pool.h>
#endif

namespace Botan {

namespace {

class Base_Hash_Engine final : public Hash_Engine {
   public:
      Base_Hash_Engine(std::unique_ptr<HashFunction> hash, std::span<const uint8_t> common_prefix) :
            Hash_Engine(common_prefix), m_hash(std::move(hash)) {}

      std::string name() const override { return m_hash->name(); }

      std::string provider() const override { return "base"; }

      size_t output_length() const override { return m_hash->output_length(); }

      size_t parallelism() const override { return 1; }

      void batch_hash(std::span<std::span<uint8_t>> outputs,
                      std::span<std::span<const uint8_t>> inputs1,
                      std::span<std::span<const uint8_t>> inputs2) override {
         check_batch_args(outputs, inputs1, inputs2);

         for(size_t i = 0; i != inputs1.size(); ++i) {
            m_hash->update(common_prefix());
            m_hash->update(inputs1[i]);
            if(!inputs2.empty()) {
               m_hash->update(inputs2[i]);
            }
            m_hash->final(outputs[i].first(output_length()));
         }
      }

   private:
      std::unique_ptr<HashFunction> m_hash;
};

std::unique_ptr<Hash_Engine> make_base_engine(std::string_view hash_fn,
                                              std::span<const uint8_t> common_prefix,
                                              std::string_view provider) {
   // SIMD specific dispatch added here later

   if(provider.empty() || provider == "base") {
      if(auto hash = HashFunction::create(hash_fn)) {
         return std::make_unique<Base_Hash_Engine>(std::move(hash), common_prefix);
      }
   }

   return nullptr;
}

#if defined(BOTAN_HAS_THREAD_UTILS)

class Threaded_Hash_Engine final : public Hash_Engine {
   public:
      Threaded_Hash_Engine(std::string_view hash_fn,
                           Thread_Pool& threadpool,
                           size_t max_threads,
                           std::span<const uint8_t> common_prefix) :
            Hash_Engine(common_prefix), m_threadpool(threadpool), m_hash_fn(hash_fn), m_max_threads(max_threads) {
         // Engines beyond the first are only instantiated once a batch is
         // actually large enough to be worth splitting over threads

         if(auto eng = make_base_engine(m_hash_fn, this->common_prefix(), "")) {
            m_engines.push_back(std::move(eng));
         } else {
            throw Lookup_Error(fmt("Could not create a hash engine for {}", m_hash_fn));
         }
      }

      std::string name() const override { return m_engines[0]->name(); }

      std::string provider() const override { return "threads"; }

      size_t output_length() const override { return m_engines[0]->output_length(); }

      size_t parallelism() const override { return m_max_threads * m_engines[0]->parallelism(); }

      void batch_hash(std::span<std::span<uint8_t>> outputs,
                      std::span<std::span<const uint8_t>> inputs1,
                      std::span<std::span<const uint8_t>> inputs2) override {
         check_batch_args(outputs, inputs1, inputs2);

         const size_t count = inputs1.size();
         if(count == 0) {
            return;
         }

         // Both inputs and outputs count towards the work estimate; for
         // XOFs with long outputs squeezing dominates. The +64 approximates
         // padding and finalization overhead.
         const size_t per_hash_bytes = common_prefix().size() + inputs1[0].size() +
                                       (inputs2.empty() ? 0 : inputs2[0].size()) + output_length() + 64;

         const size_t threads = usable_threads(count, count * per_hash_bytes);

         if(threads <= 1) {
            m_engines[0]->batch_hash(outputs, inputs1, inputs2);
            return;
         }

         while(m_engines.size() < threads) {
            auto eng = make_base_engine(m_hash_fn, common_prefix(), "");
            BOTAN_ASSERT_NONNULL(eng);  // previous attempt already succeeded
            m_engines.push_back(std::move(eng));
         }

         dispatch(threads, count, [&](size_t t, size_t offset, size_t n) {
            const auto in2 = inputs2.empty() ? inputs2 : inputs2.subspan(offset, n);
            m_engines[t]->batch_hash(outputs.subspan(offset, n), inputs1.subspan(offset, n), in2);
         });
      }

   private:
      size_t usable_threads(size_t count, size_t total_bytes) const {
         // Chunk work to not spread too thinly since just queuing the work
         // in the pool has nonzero overhead.
         constexpr size_t MIN_BYTES_PER_THREAD = 32 * 1024;

         const size_t by_bytes = std::max<size_t>(total_bytes / MIN_BYTES_PER_THREAD, 1);
         return std::min({m_max_threads, count, by_bytes});
      }

      template <typename F>
      void dispatch(size_t threads, size_t count, F work_fn) {
         const size_t per_thread = count / threads;
         const size_t remainder = count % threads;

         std::vector<std::future<void>> futures;
         futures.reserve(threads);

         size_t offset = 0;
         for(size_t t = 0; t != threads; ++t) {
            // First remainder threads get 1 extra hash over the main batch
            const size_t n = per_thread + (t < remainder ? 1 : 0);
            futures.push_back(m_threadpool.run(work_fn, t, offset, n));
            offset += n;
         }

         for(auto& f : futures) {
            f.get();
         }
      }

      Thread_Pool& m_threadpool;
      std::string m_hash_fn;
      size_t m_max_threads;
      std::vector<std::unique_ptr<Hash_Engine>> m_engines;
};

#endif

}  // namespace

void Hash_Engine::check_batch_args(std::span<std::span<uint8_t>> outputs,
                                   std::span<std::span<const uint8_t>> inputs1,
                                   std::span<std::span<const uint8_t>> inputs2) const {
   BOTAN_ARG_CHECK(outputs.size() == inputs1.size(),
                   "Hash_Engine::batch_hash requires same number of inputs and outputs");
   BOTAN_ARG_CHECK(inputs2.empty() || inputs2.size() == inputs1.size(),
                   "Hash_Engine::batch_hash second inputs must be empty or match first");

   const size_t out_len = output_length();

   for(size_t i = 0; i != inputs1.size(); ++i) {
      BOTAN_ARG_CHECK(inputs1[i].size() == inputs1[0].size(), "Hash_Engine::batch_hash inputs must be equal length");
      BOTAN_ARG_CHECK(outputs[i].size() >= out_len, "Hash_Engine::batch_hash output buffer too small");
   }

   for(size_t i = 0; i != inputs2.size(); ++i) {
      BOTAN_ARG_CHECK(inputs2[i].size() == inputs2[0].size(), "Hash_Engine::batch_hash inputs must be equal length");
   }
}

std::unique_ptr<Hash_Engine> Hash_Engine::create_or_null(std::string_view hash_fn,
                                                         std::span<const uint8_t> common_prefix,
                                                         std::string_view provider) {
#if defined(BOTAN_HAS_THREAD_UTILS)
   if(provider.empty() || provider == "threads") {
      auto& threadpool = Thread_Pool::global_instance();
      const size_t workers = threadpool.worker_count();
      if(workers >= 2) {
         return std::make_unique<Threaded_Hash_Engine>(hash_fn, threadpool, workers, common_prefix);
      }
   }
#endif

   if(auto engine = make_base_engine(hash_fn, common_prefix, provider)) {
      return engine;
   }

   return nullptr;
}

std::unique_ptr<Hash_Engine> Hash_Engine::create_or_throw(std::string_view hash_fn,
                                                          std::span<const uint8_t> common_prefix,
                                                          std::string_view provider) {
   if(auto engine = Hash_Engine::create_or_null(hash_fn, common_prefix, provider)) {
      return engine;
   } else {
      throw Lookup_Error("Hash_Engine", hash_fn, provider);
   }
}

std::vector<std::string> Hash_Engine::possible_providers(std::string_view hash_fn) {
   BOTAN_UNUSED(hash_fn);
   return {"base", "threads", "avx2", "avx512"};
}

}  // namespace Botan
