#include <botan/pwdhash.h>
#include <botan/system_rng.h>
#include <chrono>
#include <future>
#include <thread>

int main() {
   std::promise<Botan::secure_vector<uint8_t>> result_promise;
   std::future<Botan::secure_vector<uint8_t>> result_future = result_promise.get_future();

   std::jthread worker([&](std::stop_token st) {
      try {
         // Construct expensive password hash
         auto pwd_fam = Botan::PasswordHashFamily::create_or_throw("PBKDF2(SHA-256)");
         auto pwdhash = pwd_fam->from_params(static_cast<size_t>(1) << 31);
         // Derive key
         Botan::secure_vector<uint8_t> out(32);
         const auto salt = Botan::system_rng().random_array<32>();
         pwdhash->hash(out, "secret", salt, st);
         // Not canceled
         result_promise.set_value(out);
      } catch(...) {
         result_promise.set_exception(std::current_exception());
      }
   });

   // Simulate cancellation after 0.1s
   std::this_thread::sleep_for(std::chrono::milliseconds(100));
   worker.request_stop();  // asks the thread to stop

   try {
      auto key = result_future.get();
      // Handle successful derivation
   } catch(const Botan::Operation_Canceled&) {
      // Handle cancellation
   }

   // jthread joins automatically on destruction
}
