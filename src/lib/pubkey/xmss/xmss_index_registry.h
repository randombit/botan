/*
 * XMSS Index Registry
 * (C) 2016 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_XMSS_INDEX_REGISTRY_H_
#define BOTAN_XMSS_INDEX_REGISTRY_H_

#include <botan/mutex.h>
#include <botan/internal/atomic.h>
#include <array>
#include <memory>
#include <span>
#include <vector>

namespace Botan {

/**
 * A registry for XMSS private keys, keeps track of the leaf index for
 * independent copies of the same key.
 **/
class XMSS_Index_Registry final {
   public:
      XMSS_Index_Registry(const XMSS_Index_Registry&) = delete;
      XMSS_Index_Registry(XMSS_Index_Registry&&) = delete;
      XMSS_Index_Registry& operator=(const XMSS_Index_Registry&) = delete;
      XMSS_Index_Registry& operator=(XMSS_Index_Registry&&) = delete;
      ~XMSS_Index_Registry();

      /**
       * Retrieves a handle to the process-wide unique XMSS index registry.
       *
       * @return Reference to unique XMSS index registry.
       **/
      static XMSS_Index_Registry& get_instance();

      /**
       * Retrieves the last unused leaf index for the private key identified
       * by private_seed and prf. The leaf index will be updated properly
       * across independent copies of private_key. If the key is not yet
       * registered, a new entry is created with leaf index 0.
       *
       * @param params The XMSS parameter identifier
       * @param private_seed Part of the unique identifier for an
       *                     XMSS_PrivateKey.
       * @param prf Part of the unique identifier for an XMSS_PrivateKey.
       *
       * @return last unused leaf index for private_key.
       **/
      std::shared_ptr<Atomic<size_t>> get(uint32_t params,
                                          std::span<const uint8_t> private_seed,
                                          std::span<const uint8_t> prf);

   private:
      using key_id_t = std::array<uint8_t, 32>;

      struct Entry {
            key_id_t key_id;
            std::shared_ptr<Atomic<size_t>> leaf_index;
      };

      XMSS_Index_Registry();

      std::vector<Entry> m_registry;
      mutex_type m_mutex;
};

}  // namespace Botan

#endif
