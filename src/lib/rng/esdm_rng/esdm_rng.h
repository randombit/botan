/*
* ESDM RNG
* (C) 2024, Markus Theil <theil.markus@gmail.com>
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ESDM_RNG_H_
#define BOTAN_ESDM_RNG_H_

#include <botan/rng.h>
#include <memory>

namespace Botan {

/**
* Return a shared reference to a global PRNG instance provided by ESDM
*/
BOTAN_PUBLIC_API(3, 7) RandomNumberGenerator& esdm_rng();

/**
* Entropy Source and DRNG Manager (ESDM) is a Linux/Unix based
* PRNG manager, which can be seeded from NTG.1/SP800-90B sources.
*
* See:
*  - Repository: https://github.com/smuellerDD/esdm
*  - Further Docs: https://www.chronox.de/esdm/index.html
*
* Different entropy sources can be configured in respect of being
* active and how much entropy is accounted for each of them.
*
* ESDM tracks its seed and reseed status and blocks, when not fully seeded.
* For this functionality, the esdm_rpcc_get_random_bytes_pr (prediction resistant) or
* esdm_rpcc_get_random_bytes_full (fully seeded) calls have to be used.
*
* Configurable modes:
*   - fully seeded (-> fast): provide entropy from a DRBG/PRNG after beeing fully seeded,
*          block until this point is reached, reseed from after a time
*          and/or invocation limit, block again if reseeding is not possible
*   - prediction resistance (-> slow): reseed ESDM with fresh entropy after each invocation
*
* You typically want to use the fast fully seeded mode, which is the default.
*
* Instances of this class communicate over RPC with ESDM. The esdm_rpc_client
* library, provided by ESDM, is leveraged for this.
*
* Thread safety:
*   It is fine to construct, destruct and use objects of this class concurrently.
*   The communication with ESDM is thread-safe, as handled by esdm_rpc_client.
*   The initialization of esdm_rpc_client is not thread safe, therefore this class
*   takes care of it, with its embedded ESDM_Context.
*/
class BOTAN_PUBLIC_API(3, 7) ESDM_RNG final : public Botan::RandomNumberGenerator {
   public:
      /**
      * Default constructor for ESDM, fully seeded mode
      */
      ESDM_RNG() : ESDM_RNG(false) {}

      /**
      * Construct ESDM instance with configurable mode
      */
      explicit ESDM_RNG(bool prediction_resistance);

      std::string name() const override {
         if(m_prediction_resistance) {
            return "esdm-pr";
         } else {
            return "esdm-full";
         }
      }

      /**
      * ESDM blocks, if it is not seeded,
      *
      * @return true
      */
      bool is_seeded() const override { return true; }

      /**
      * ESDM can inject additional inputs
      * but we do not account entropy for it
      *
      * @return true
      */
      bool accepts_input() const override { return true; }

      /**
      * the ESDM RNG does not hold any state outside ESDM, that should be cleared
      * here
      */
      void clear() override {}

   protected:
      void fill_bytes_with_input(std::span<uint8_t> out, std::span<const uint8_t> in) override;

   private:
      /**
      * tracks if predicition resistant or fully seeded interface should be queried
      */
      bool m_prediction_resistance;

      /**
      * takes care of thread-safe esdm_rpc_client initialization
      */
      std::shared_ptr<void> m_ctx;
};

}  // namespace Botan

#endif /* BOTAN_ESDM_RNG_H_ */
