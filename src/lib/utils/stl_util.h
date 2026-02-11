/*
* STL Utility Functions
* (C) 1999-2007 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
* (C) 2023-2024 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_STL_UTIL_H_
#define BOTAN_STL_UTIL_H_

#include <botan/assert.h>
#include <variant>
#include <vector>

namespace Botan {

/**
 * Reduce the values of @p keys into an accumulator initialized with @p acc using
 * the reducer function @p reducer.
 *
 * The @p reducer is a function taking the accumulator and a single key to return the
 * new accumulator. Keys are consecutively reduced into the accumulator.
 *
 * @return the accumulator containing the reduction of @p keys
 */
template <typename RetT, typename KeyT, typename ReducerT>
RetT reduce(const std::vector<KeyT>& keys, RetT acc, ReducerT reducer)
   requires std::invocable<ReducerT&, RetT, const KeyT&> &&
            std::convertible_to<std::invoke_result_t<ReducerT&, RetT, const KeyT&>, RetT>
{
   for(const KeyT& key : keys) {
      acc = reducer(std::move(acc), key);
   }
   return acc;
}

/**
* Existence check for values
*/
template <typename T, typename V>
bool value_exists(const std::vector<T>& vec, const V& val) {
   for(const auto& elem : vec) {
      if(elem == val) {
         return true;
      }
   }
   return false;
}

template <typename T, typename Pred>
void map_remove_if(Pred pred, T& assoc) {
   auto i = assoc.begin();
   while(i != assoc.end()) {
      if(pred(i->first)) {
         assoc.erase(i++);
      } else {
         i++;
      }
   }
}

template <typename... Alts, typename... Ts>
constexpr bool holds_any_of(const std::variant<Ts...>& v) noexcept {
   return (std::holds_alternative<Alts>(v) || ...);
}

template <typename GeneralVariantT, typename SpecialT>
constexpr bool is_generalizable_to(const SpecialT& /*unnamed*/) noexcept {
   return std::is_constructible_v<GeneralVariantT, SpecialT>;
}

template <typename GeneralVariantT, typename... SpecialTs>
constexpr bool is_generalizable_to(const std::variant<SpecialTs...>& /*unnamed*/) noexcept {
   return (std::is_constructible_v<GeneralVariantT, SpecialTs> && ...);
}

/**
 * @brief Converts a given variant into another variant-ish whose type states
 *        are a super set of the given variant.
 *
 * This is useful to convert restricted variant types into more general
 * variants types.
 */
template <typename GeneralVariantT, typename SpecialT>
constexpr GeneralVariantT generalize_to(SpecialT&& specific)
   requires(std::is_constructible_v<GeneralVariantT, std::decay_t<SpecialT>>)
{
   return std::forward<SpecialT>(specific);
}

/**
 * @brief Converts a given variant into another variant-ish whose type states
 *        are a super set of the given variant.
 *
 * This is useful to convert restricted variant types into more general
 * variants types.
 */
template <typename GeneralVariantT, typename... SpecialTs>
constexpr GeneralVariantT generalize_to(std::variant<SpecialTs...> specific) {
   static_assert(
      is_generalizable_to<GeneralVariantT>(specific),
      "Desired general type must be implicitly constructible by all types of the specialized std::variant<>");
   return std::visit([](auto s) -> GeneralVariantT { return s; }, std::move(specific));
}

// This is a helper utility to emulate pattern matching with std::visit.
// See https://en.cppreference.com/w/cpp/utility/variant/visit for more info.
template <class... Ts>
struct overloaded : Ts... {
      using Ts::operator()...;
};
// explicit deduction guide (not needed as of C++20)
template <class... Ts>
overloaded(Ts...) -> overloaded<Ts...>;

// TODO: C++23: replace with std::to_underlying
template <typename T>
   requires std::is_enum_v<T>
auto to_underlying(T e) noexcept {
   return static_cast<std::underlying_type_t<T>>(e);
}

// TODO: C++23 - use std::out_ptr
template <typename T>
[[nodiscard]] constexpr auto out_ptr(T& outptr) noexcept {
   class out_ptr_t {
      public:
         constexpr ~out_ptr_t() noexcept {
            m_ptr.reset(m_rawptr);
            m_rawptr = nullptr;
         }

         constexpr explicit out_ptr_t(T& outptr) noexcept : m_ptr(outptr), m_rawptr(nullptr) {}

         out_ptr_t(const out_ptr_t&) = delete;
         out_ptr_t(out_ptr_t&&) = delete;
         out_ptr_t& operator=(const out_ptr_t&) = delete;
         out_ptr_t& operator=(out_ptr_t&&) = delete;

         // NOLINTNEXTLINE(*-explicit-conversions) - Implicit by design for C API interop
         [[nodiscard]] constexpr operator typename T::element_type **() && noexcept { return &m_rawptr; }

      private:
         T& m_ptr;
         typename T::element_type* m_rawptr;
   };

   return out_ptr_t{outptr};
}

}  // namespace Botan

#endif
