#include <iostream>

#include <botan/asio_compat.h>
#if defined(BOTAN_FOUND_COMPATIBLE_BOOST_ASIO_VERSION) && defined(BOTAN_HAS_THREAD_UTILS) && defined(BOTAN_HAS_ARGON2)

   #include <botan/hex.h>
   #include <botan/pwdhash.h>
   #include <botan/work_executor.h>

   #include <boost/asio.hpp>

   #include <array>
   #include <atomic>
   #include <vector>

// Routes the library's parallel work onto an application owned Asio pool
class Pool_Executor final : public Botan::Work_Executor {
   public:
      explicit Pool_Executor(size_t threads) : m_pool(threads), m_threads(threads) {}

      void queue_work(std::function<void()> work) override {
         m_queued += 1;

         // Work queued from one of the pool's own threads runs directly.
         // Otherwise, if every thread were inside a library operation waiting
         // on work it had queued, none of that work could ever run.
         if(m_pool.get_executor().running_in_this_thread()) {
            work();
         } else {
            boost::asio::post(m_pool, std::move(work));
         }
      }

      size_t max_concurrency() const override { return m_threads; }

      size_t queued() const { return m_queued.load(); }

   private:
      boost::asio::thread_pool m_pool;
      size_t m_threads;
      std::atomic<size_t> m_queued = 0;
};

int main() {
   try {
      // Install before any other use of the library, so that its own thread
      // pool is never started. The executor remains in use for the rest of
      // the process.
      auto executor = std::make_shared<Pool_Executor>(4);
      Botan::Work_Executor::set_global(executor);

      // Argon2 with several lanes computes each lane as a separate piece of work
      constexpr size_t memory_kib = 64 * 1024;
      constexpr size_t iterations = 2;
      constexpr size_t lanes = 4;

      auto argon2 = Botan::PasswordHashFamily::create_or_throw("Argon2id")->from_params(memory_kib, iterations, lanes);

      // A fixed salt so that the output is reproducible; real uses must
      // generate a random one
      const std::string_view password = "tell no one";
      const std::vector<uint8_t> salt(16, 0x42);
      std::array<uint8_t, 32> key{};

      argon2->hash(key, password, salt);

      std::cout << argon2->to_string() << ": " << Botan::hex_encode(key) << '\n';
      std::cout << "Work items dispatched to the application pool: " << executor->queued() << '\n';
   } catch(std::exception& e) {
      std::cerr << "Uncaught exception: " << e.what() << "\n";
   } catch(...) {
      std::cerr << "Uncaught exception: (unknown)\n";
   }
   return 0;
}

#else

int main() {
   std::cout << "This example requires Boost.Asio, Argon2, and thread support\n";
   return 0;
}

#endif
