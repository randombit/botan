/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_engine.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/hash.h>
#include <algorithm>

#if defined(BOTAN_HAS_THREAD_UTILS)
   #include <botan/internal/rounding.h>
   #include <botan/internal/thread_pool.h>
   #include <atomic>
   #include <exception>
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
                           std::unique_ptr<Hash_Engine> first_engine,
                           std::span<const uint8_t> common_prefix) :
            Hash_Engine(common_prefix), m_hash_fn(hash_fn) {
         // Engines beyond the first are only instantiated once a batch is
         // actually large enough to be worth splitting over threads
         BOTAN_ASSERT_NONNULL(first_engine);
         m_engines.push_back(std::move(first_engine));
      }

      std::string name() const override { return m_engines[0]->name(); }

      std::string provider() const override { return "threads"; }

      size_t output_length() const override { return m_engines[0]->output_length(); }

      size_t parallelism() const override { return std::max<size_t>(max_threads(), 1) * m_engines[0]->parallelism(); }

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

         // Chunk work to not spread too thinly since just queuing the work
         // in the pool has nonzero overhead.
         constexpr size_t MIN_BYTES_PER_THREAD = 32 * 1024;
         const size_t by_bytes = (count * per_hash_bytes) / MIN_BYTES_PER_THREAD;

         // Checked before consulting the pool, so that it is not created
         // until there is a batch actually worth splitting
         if(count < 2 || by_bytes < 2) {
            m_engines[0]->batch_hash(outputs, inputs1, inputs2);
            return;
         }

         const size_t threads = std::min({max_threads(), count, by_bytes});

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
      // Touching the global pool creates its threads, so defer that until
      // the worker count is actually needed
      size_t max_threads() const {
         if(m_pool == nullptr) {
            m_pool = &Thread_Pool::global_instance();
            m_max_threads = m_pool->worker_count();
         }
         return m_max_threads;
      }

      template <typename F>
      void dispatch(size_t threads, size_t count, F work_fn) {
         const size_t lanes = m_engines[0]->parallelism();
         const size_t chunk = std::max(lanes, round_up(count / (4 * threads), lanes));

         std::atomic<size_t> next = 0;

         auto claim_chunks = [&](size_t t) {
            for(;;) {
               const size_t offset = next.fetch_add(chunk);
               if(offset >= count) {
                  break;
               }
               work_fn(t, offset, std::min(chunk, count - offset));
            }
         };

         // The calling thread works through chunks as well, using the
         // last engine, rather than just waiting on the pool
         std::vector<std::future<void>> futures;
         futures.reserve(threads - 1);

         for(size_t t = 0; t != threads - 1; ++t) {
            futures.push_back(m_pool->run(claim_chunks, t));
         }

         // The workers reference this frame, so whatever happens every
         // one of them must have finished before returning or unwinding
         std::exception_ptr error;

         try {
            // Hash the last chunk in the current thread:
            claim_chunks(threads - 1);
         } catch(...) {
            error = std::current_exception();
         }

         for(auto& f : futures) {
            try {
               f.get();
            } catch(...) {
               if(!error) {
                  error = std::current_exception();
               }
            }
         }

         if(error) {
            std::rethrow_exception(error);
         }
      }

      std::string m_hash_fn;
      mutable Thread_Pool* m_pool = nullptr;
      mutable size_t m_max_threads = 0;
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
      // An explicit request for threads fails if the pool is disabled. The
      // default does not consult the pool here, since doing so creates its
      // threads; the engine only does that once a batch is worth splitting.
      if(provider == "threads" && Thread_Pool::global_instance().worker_count() < 2) {
         return nullptr;
      }

      if(auto engine = make_base_engine(hash_fn, common_prefix, "")) {
         return std::make_unique<Threaded_Hash_Engine>(hash_fn, std::move(engine), common_prefix);
      }

      return nullptr;
   }
#endif

   return make_base_engine(hash_fn, common_prefix, provider);
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
