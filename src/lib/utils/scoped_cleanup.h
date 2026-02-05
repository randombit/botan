/*
* (C) 2023-2024 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SCOPED_CLEANUP_H_
#define BOTAN_SCOPED_CLEANUP_H_

#include <concepts>
#include <optional>
#include <utility>

namespace Botan {

/**
 * @brief Helper class to create a RAII-style cleanup callback
 *
 * Ensures that the cleanup callback given in the object's constructor is called
 * when the object is destroyed. Use this to ensure some cleanup code runs when
 * leaving the current scope.
 */
template <std::invocable FunT>
class scoped_cleanup final {
   public:
      explicit scoped_cleanup(FunT cleanup) : m_cleanup(std::move(cleanup)) {}

      scoped_cleanup(const scoped_cleanup&) = delete;
      scoped_cleanup& operator=(const scoped_cleanup&) = delete;

      scoped_cleanup(scoped_cleanup&& other) noexcept : m_cleanup(std::move(other.m_cleanup)) { other.disengage(); }

      scoped_cleanup& operator=(scoped_cleanup&& other) noexcept {
         if(this != &other) {
            m_cleanup = std::move(other.m_cleanup);
            other.disengage();
         }
         return *this;
      }

      ~scoped_cleanup() {
         if(m_cleanup.has_value()) {
            m_cleanup.value()();
         }
      }

      /**
       * Disengage the cleanup callback, i.e., prevent it from being called
       */
      void disengage() noexcept { m_cleanup.reset(); }

   private:
      std::optional<FunT> m_cleanup;
};

}  // namespace Botan

#endif
