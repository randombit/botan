/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_engine.h>

#include <botan/assert.h>
#include <botan/hash.h>

#if defined(BOTAN_HAS_THREAD_UTILS)
   #include <botan/internal/thread_pool.h>
#endif

namespace Botan {

namespace {

class Base_Hash_Engine final : public Hash_Engine {
   public:
      explicit Base_Hash_Engine(std::unique_ptr<HashFunction> hash) : m_hash(std::move(hash)) {}

      std::string name() const override { return m_hash->name(); }

      std::string provider() const override { return "base"; }

      size_t output_length() const override { return m_hash->output_length(); }

      size_t parallelism() const override { return 1; }

      void batch_hash(std::span<std::span<uint8_t>> outputs, std::span<std::span<const uint8_t>> inputs) override {
         BOTAN_ARG_CHECK(outputs.size() == inputs.size(),
                         "Hash_Engine::batch_hash requires same number of inputs and outputs");

         for(size_t i = 0; i != inputs.size(); ++i) {
            BOTAN_ARG_CHECK(outputs[i].size() >= output_length(), "Hash_Engine::batch_hash output buffer too small");
            m_hash->update(inputs[i]);
            m_hash->final(outputs[i].first(output_length()));
         }
      }

   private:
      std::unique_ptr<HashFunction> m_hash;
};

#if defined(BOTAN_HAS_THREAD_UTILS)

class Threaded_Hash_Engine final : public Hash_Engine {
   public:
      Threaded_Hash_Engine(std::unique_ptr<HashFunction> hash, Thread_Pool& threadpool) :
            m_threadpool(threadpool),
            m_name(hash->name()),
            m_output_length(hash->output_length()),
            m_thread_count(m_threadpool.worker_count()) {
         BOTAN_ASSERT_NOMSG(m_thread_count > 0);
         m_hashes.reserve(m_thread_count);
         for(size_t i = 0; i != m_thread_count; ++i) {
            m_hashes.push_back(hash->new_object());
         }
      }

      std::string name() const override { return m_name; }

      std::string provider() const override { return "threads"; }

      size_t output_length() const override { return m_output_length; }

      size_t parallelism() const override { return m_thread_count; }

      void batch_hash(std::span<std::span<uint8_t>> outputs, std::span<std::span<const uint8_t>> inputs) override {
         BOTAN_ARG_CHECK(outputs.size() == inputs.size(),
                         "Hash_Engine::batch_hash requires same number of inputs and outputs");

         const size_t count = inputs.size();
         const size_t threads = usable_threads(count);

         if(threads <= 1) {
            hash_chunk(*m_hashes[0], m_output_length, outputs, inputs, 0, count);
            return;
         }

         dispatch(threads, count, [&](size_t t, size_t offset, size_t n) {
            hash_chunk(*m_hashes[t], m_output_length, outputs, inputs, offset, n);
         });
      }

   private:
      size_t usable_threads(size_t count) const {
         // Chunk work to not spread too thinly since just queuing the work
         // in the pool has nonzero overhead.
         constexpr size_t MIN_HASHES_PER_THREAD = 64;

         const size_t max_useful_threads = count / MIN_HASHES_PER_THREAD;
         return std::min(m_thread_count, std::max<size_t>(max_useful_threads, 1));
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

      static void hash_chunk(HashFunction& hash,
                             size_t output_length,
                             std::span<std::span<uint8_t>> outputs,
                             std::span<std::span<const uint8_t>> inputs,
                             size_t offset,
                             size_t count) {
         for(size_t i = offset; i != offset + count; ++i) {
            hash.update(inputs[i]);
            hash.final(outputs[i].first(output_length));
         }
      }

      Thread_Pool& m_threadpool;
      std::string m_name;
      size_t m_output_length;
      size_t m_thread_count;
      std::vector<std::unique_ptr<HashFunction>> m_hashes;
};

#endif

}  // namespace

std::unique_ptr<Hash_Engine> Hash_Engine::create_or_throw(std::string_view hash_fn) {
   auto hash = HashFunction::create_or_throw(hash_fn);

#if defined(BOTAN_HAS_THREAD_UTILS)
   auto& threadpool = Thread_Pool::global_instance();
   if(threadpool.worker_count() > 0) {
      return std::make_unique<Threaded_Hash_Engine>(std::move(hash), threadpool);
   }
#endif

   return std::make_unique<Base_Hash_Engine>(std::move(hash));
}

}  // namespace Botan
