/*
* STL Utility Functions
* (C) 1999-2007 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_STL_UTIL_H_
#define BOTAN_STL_UTIL_H_

#include <algorithm>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <tuple>
#include <variant>
#include <vector>

#include <botan/concepts.h>
#include <botan/secmem.h>
#include <botan/strong_type.h>

namespace Botan {

template <concepts::contiguous_container T = std::vector<uint8_t>>
inline T to_byte_vector(std::string_view s) {
   return T(s.cbegin(), s.cend());
}

inline std::string to_string(std::span<const uint8_t> bytes) {
   return std::string(bytes.begin(), bytes.end());
}

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
   requires std::is_convertible_v<ReducerT, std::function<RetT(RetT, const KeyT&)>>
{
   for(const KeyT& key : keys) {
      acc = reducer(std::move(acc), key);
   }
   return acc;
}

/**
* Existence check for values
*/
template <typename T, typename OT>
bool value_exists(const std::vector<T>& vec, const OT& val) {
   for(size_t i = 0; i != vec.size(); ++i) {
      if(vec[i] == val) {
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

/**
 * Helper class to ease unmarshalling of concatenated fixed-length values
 */
class BufferSlicer final {
   public:
      BufferSlicer(std::span<const uint8_t> buffer) : m_remaining(buffer) {}

      template <concepts::contiguous_container ContainerT>
      auto copy(const size_t count) {
         const auto result = take(count);
         return ContainerT(result.begin(), result.end());
      }

      auto copy_as_vector(const size_t count) { return copy<std::vector<uint8_t>>(count); }

      auto copy_as_secure_vector(const size_t count) { return copy<secure_vector<uint8_t>>(count); }

      std::span<const uint8_t> take(const size_t count) {
         BOTAN_STATE_CHECK(remaining() >= count);
         auto result = m_remaining.first(count);
         m_remaining = m_remaining.subspan(count);
         return result;
      }

      template <size_t count>
      std::span<const uint8_t, count> take() {
         BOTAN_STATE_CHECK(remaining() >= count);
         auto result = m_remaining.first<count>();
         m_remaining = m_remaining.subspan(count);
         return result;
      }

      template <concepts::contiguous_strong_type T>
      StrongSpan<const T> take(const size_t count) {
         return StrongSpan<const T>(take(count));
      }

      uint8_t take_byte() { return take(1)[0]; }

      void copy_into(std::span<uint8_t> sink) {
         const auto data = take(sink.size());
         std::copy(data.begin(), data.end(), sink.begin());
      }

      void skip(const size_t count) { take(count); }

      size_t remaining() const { return m_remaining.size(); }

      bool empty() const { return m_remaining.empty(); }

   private:
      std::span<const uint8_t> m_remaining;
};

/**
 * @brief Helper class to ease in-place marshalling of concatenated fixed-length
 *        values.
 *
 * The size of the final buffer must be known from the start, reallocations are
 * not performed.
 */
class BufferStuffer {
   public:
      constexpr BufferStuffer(std::span<uint8_t> buffer) : m_buffer(buffer) {}

      /**
       * @returns a span for the next @p bytes bytes in the concatenated buffer.
       *          Checks that the buffer is not exceded.
       */
      constexpr std::span<uint8_t> next(size_t bytes) {
         BOTAN_STATE_CHECK(m_buffer.size() >= bytes);

         auto result = m_buffer.first(bytes);
         m_buffer = m_buffer.subspan(bytes);
         return result;
      }

      template <size_t bytes>
      constexpr std::span<uint8_t, bytes> next() {
         BOTAN_STATE_CHECK(m_buffer.size() >= bytes);

         auto result = m_buffer.first<bytes>();
         m_buffer = m_buffer.subspan(bytes);
         return result;
      }

      template <concepts::contiguous_strong_type StrongT>
      StrongSpan<StrongT> next(size_t bytes) {
         return StrongSpan<StrongT>(next(bytes));
      }

      /**
       * @returns a reference to the next single byte in the buffer
       */
      constexpr uint8_t& next_byte() { return next(1)[0]; }

      constexpr void append(std::span<const uint8_t> buffer) {
         auto sink = next(buffer.size());
         std::copy(buffer.begin(), buffer.end(), sink.begin());
      }

      constexpr void append(uint8_t b, size_t repeat = 1) {
         auto sink = next(repeat);
         std::fill(sink.begin(), sink.end(), b);
      }

      constexpr bool full() const { return m_buffer.empty(); }

      constexpr size_t remaining_capacity() const { return m_buffer.size(); }

   private:
      std::span<uint8_t> m_buffer;
};

/**
 * Concatenate an arbitrary number of buffers.
 * @return the concatenation of \p buffers as the container type of the first buffer
 */
template <typename... Ts>
decltype(auto) concat(Ts&&... buffers) {
   static_assert(sizeof...(buffers) > 0, "concat requires at least one buffer");

   using result_t = std::remove_cvref_t<std::tuple_element_t<0, std::tuple<Ts...>>>;
   result_t result;
   result.reserve((buffers.size() + ...));
   (result.insert(result.end(), buffers.begin(), buffers.end()), ...);
   return result;
}

/**
 * Concatenate an arbitrary number of buffers and define the output buffer
 * type as a mandatory template parameter.
 * @return the concatenation of \p buffers as the user-defined container type
 */
template <typename ResultT, typename... Ts>
ResultT concat_as(Ts&&... buffers) {
   return concat(ResultT(), std::forward<Ts>(buffers)...);
}

template <typename... Alts, typename... Ts>
constexpr bool holds_any_of(const std::variant<Ts...>& v) noexcept {
   return (std::holds_alternative<Alts>(v) || ...);
}

template <typename GeneralVariantT, typename SpecialT>
constexpr bool is_generalizable_to(const SpecialT&) noexcept {
   return std::is_constructible_v<GeneralVariantT, SpecialT>;
}

template <typename GeneralVariantT, typename... SpecialTs>
constexpr bool is_generalizable_to(const std::variant<SpecialTs...>&) noexcept {
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
constexpr GeneralVariantT generalize_to(SpecialT&& specific) noexcept
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
constexpr GeneralVariantT generalize_to(std::variant<SpecialTs...> specific) noexcept {
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

/**
 * @brief Helper class to create a RAII-style cleanup callback
 *
 * Ensures that the cleanup callback given in the object's constructor is called
 * when the object is destroyed. Use this to ensure some cleanup code runs when
 * leaving the current scope.
 */
template <std::invocable FunT>
class scoped_cleanup {
   public:
      explicit scoped_cleanup(FunT cleanup) : m_cleanup(std::move(cleanup)) {}

      scoped_cleanup(const scoped_cleanup&) = delete;
      scoped_cleanup& operator=(const scoped_cleanup&) = delete;
      scoped_cleanup(scoped_cleanup&&) = delete;
      scoped_cleanup& operator=(scoped_cleanup&&) = delete;

      ~scoped_cleanup() {
         if(m_cleanup.has_value()) {
            m_cleanup.value()();
         }
      }

      /**
       * Disengage the cleanup callback, i.e., prevent it from being called
       */
      void disengage() { m_cleanup.reset(); }

   private:
      std::optional<FunT> m_cleanup;
};

/**
 * @brief Helper class to pass literal strings to C++ templates
 */
template <size_t N>
class StringLiteral {
   public:
      constexpr StringLiteral(const char (&str)[N]) { std::copy_n(str, N, value); }

      char value[N];
};

}  // namespace Botan

#endif
