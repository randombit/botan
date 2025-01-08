/*
* ESDM RNG
* (C) 2024, Markus Theil <theil.markus@gmail.com>
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/esdm_rng.h>

#include <esdm/esdm_rpc_client.h>
#include <mutex>

namespace Botan {

namespace {
/**
* This helper makes sure that the ESDM service is initialized and
* finalized as needed in a threadsafe fashion. Finalization happens
* as soon as all instances of ESDM_RNG are destructed. This may
* happen multiple times in the lifetime of the process.
*/
class ESDM_Context {
   public:
      [[nodiscard]] static std::shared_ptr<void> instance() {
         static ESDM_Context g_instance;
         return g_instance.acquire();
      }

   private:
      ESDM_Context() = default;

      [[nodiscard]] std::shared_ptr<void> acquire() {
         std::scoped_lock lk(m_mutex);
         if(m_refs++ == 0) {
            if(esdm_rpcc_init_unpriv_service(nullptr) != 0) {
               throw Botan::System_Error("unable to initialize ESDM unprivileged service");
            }
         }
         return std::shared_ptr<void>{nullptr, [this](void*) { this->release(); }};
      }

      void release() {
         std::scoped_lock lk(m_mutex);
         if(m_refs-- == 1) {
            esdm_rpcc_fini_unpriv_service();
         }
      }

   private:
      std::mutex m_mutex;
      size_t m_refs = 0;
};
}  // namespace

ESDM_RNG::ESDM_RNG(bool prediction_resistance) :
      m_prediction_resistance(prediction_resistance), m_ctx(ESDM_Context::instance()) {}

void ESDM_RNG::fill_bytes_with_input(std::span<uint8_t> out, std::span<const uint8_t> in) {
   /*
   * This variable is implicitly set by the "esdm_invoke" macro that comes
   * with the ESDM library. "esdm_invoke" implements a retry mechanism for
   * the underlying RPC mechanism of ESDM.
   */
   ssize_t ret = 0;

   if(!in.empty()) {
      ret = 0;

      /*
      * take additional input, but do not account entropy for it,
      * as this information is not included in the API
      */
      esdm_invoke(esdm_rpcc_write_data(in.data(), in.size()));
      /*
      * ret was set by esdm_invoke, as mentioned above
      */
      if(ret != 0) {
         throw Botan::System_Error("Writing additional input to ESDM failed");
      }
   }

   if(!out.empty()) {
      ret = 0;

      if(m_prediction_resistance) {
         esdm_invoke(esdm_rpcc_get_random_bytes_pr(out.data(), out.size()));
      } else {
         esdm_invoke(esdm_rpcc_get_random_bytes_full(out.data(), out.size()));
      }
      /*
      * ret was set by esdm_invoke, as mentioned above
      */
      if(ret != static_cast<ssize_t>(out.size())) {
         throw Botan::System_Error("Fetching random bytes from ESDM failed");
      }
   }
}

RandomNumberGenerator& esdm_rng() {
   static ESDM_RNG g_esdm_rng;
   return g_esdm_rng;
}

}  // namespace Botan
