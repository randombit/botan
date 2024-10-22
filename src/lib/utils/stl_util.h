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

namespace detail {

/**
 * Helper function that performs range size-checks as required given the
 * selected output and input range types. If all lengths are known at compile
 * time, this check will be performed at compile time as well. It will then
 * instantiate an output range and concatenate the input ranges' contents.
 */
template <ranges::spanable_range OutR, ranges::spanable_range... Rs>
constexpr OutR concatenate(Rs&&... ranges)
   requires(concepts::reservable_container<OutR> || ranges::statically_spanable_range<OutR>)
{
   OutR result;

   // Prepare and validate the output range and construct a lambda that does the
   // actual filling of the result buffer.
   // (if no input ranges are given, GCC claims that fill_fn is unused)
   [[maybe_unused]] auto fill_fn = [&] {
      if constexpr(concepts::reservable_container<OutR>) {
         // dynamically allocate the correct result byte length
         const size_t total_size = (ranges.size() + ... + 0);
         result.reserve(total_size);

         // fill the result buffer using a back-inserter
         return [&result](auto&& range) {
            std::copy(
               std::ranges::begin(range), std::ranges::end(range), std::back_inserter(unwrap_strong_type(result)));
         };
      } else {
         if constexpr((ranges::statically_spanable_range<Rs> && ... && true)) {
            // all input ranges have a static extent, so check the total size at compile time
            // (work around an issue in MSVC that warns `total_size` is unused)
            [[maybe_unused]] constexpr size_t total_size = (decltype(std::span{ranges})::extent + ... + 0);
            static_assert(result.size() == total_size, "size of result buffer does not match the sum of input buffers");
         } else {
            // at least one input range has a dynamic extent, so check the total size at runtime
            const size_t total_size = (ranges.size() + ... + 0);
            BOTAN_ARG_CHECK(result.size() == total_size,
                            "result buffer has static extent that does not match the sum of input buffers");
         }

         // fill the result buffer and hold the current output-iterator position
         return [itr = std::ranges::begin(result)](auto&& range) mutable {
            std::copy(std::ranges::begin(range), std::ranges::end(range), itr);
            std::advance(itr, std::ranges::size(range));
         };
      }
   }();

   // perform the actual concatenation
   (fill_fn(std::forward<Rs>(ranges)), ...);

   return result;
}

}  // namespace detail

/**
 * Concatenate an arbitrary number of buffers. Performs range-checks as needed.
 *
 * The output type can be auto-detected based on the input ranges, or explicitly
 * specified by the caller. If all input ranges have a static extent, the total
 * size is calculated at compile time and a statically sized std::array<> is used.
 * Otherwise this tries to use the type of the first input range as output type.
 *
 * Alternatively, the output container type can be specified explicitly.
 */
template <typename OutR = detail::AutoDetect, ranges::spanable_range... Rs>
constexpr auto concat(Rs&&... ranges)
   requires(all_same_v<std::ranges::range_value_t<Rs>...>)
{
   if constexpr(std::same_as<detail::AutoDetect, OutR>) {
      // Try to auto-detect a reasonable output type given the input ranges
      static_assert(sizeof...(Rs) > 0, "Cannot auto-detect the output type if not a single input range is provided.");
      using candidate_result_t = std::remove_cvref_t<std::tuple_element_t<0, std::tuple<Rs...>>>;
      using result_range_value_t = std::remove_cvref_t<std::ranges::range_value_t<candidate_result_t>>;

      if constexpr((ranges::statically_spanable_range<Rs> && ...)) {
         // If all input ranges have a static extent, we can calculate the total size at compile time
         // and therefore can use a statically sized output container. This is constexpr.
         constexpr size_t total_size = (decltype(std::span{ranges})::extent + ... + 0);
         using out_array_t = std::array<result_range_value_t, total_size>;
         return detail::concatenate<out_array_t>(std::forward<Rs>(ranges)...);
      } else {
         // If at least one input range has a dynamic extent, we must use a dynamically allocated output container.
         // We assume that the user wants to use the first input range's container type as output type.
         static_assert(
            concepts::reservable_container<candidate_result_t>,
            "First input range has static extent, but a dynamically allocated output range is required. Please explicitly specify a dynamically allocatable output type.");
         return detail::concatenate<candidate_result_t>(std::forward<Rs>(ranges)...);
      }
   } else {
      // The caller has explicitly specified the output type
      return detail::concatenate<OutR>(std::forward<Rs>(ranges)...);
   }
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

      scoped_cleanup(scoped_cleanup&& other) : m_cleanup(std::move(other.m_cleanup)) { other.disengage(); }

      scoped_cleanup& operator=(scoped_cleanup&& other) {
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
      void disengage() { m_cleanup.reset(); }

   private:
      std::optional<FunT> m_cleanup;
};

/**
* Define BOTAN_ASSERT_IS_SOME
*/
template <typename T>
T assert_is_some(std::optional<T> v, const char* expr, const char* func, const char* file, int line) {
   if(v) {
      return *v;
   } else {
      Botan::assertion_failure(expr, "optional had value", func, file, line);
   }
}

#define BOTAN_ASSERT_IS_SOME(v) assert_is_some(v, #v, __func__, __FILE__, __LINE__)

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

         constexpr out_ptr_t(T& outptr) noexcept : m_ptr(outptr), m_rawptr(nullptr) {}

         out_ptr_t(const out_ptr_t&) = delete;
         out_ptr_t(out_ptr_t&&) = delete;
         out_ptr_t& operator=(const out_ptr_t&) = delete;
         out_ptr_t& operator=(out_ptr_t&&) = delete;

         [[nodiscard]] constexpr operator typename T::element_type **() && noexcept { return &m_rawptr; }

      private:
         T& m_ptr;
         typename T::element_type* m_rawptr;
   };

   return out_ptr_t{outptr};
}

template <typename T>
   requires std::is_default_constructible_v<T>
[[nodiscard]] constexpr auto out_opt(std::optional<T>& outopt) noexcept {
   class out_opt_t {
      public:
         constexpr ~out_opt_t() noexcept { m_opt = m_raw; }

         constexpr out_opt_t(std::optional<T>& outopt) noexcept : m_opt(outopt) {}

         out_opt_t(const out_opt_t&) = delete;
         out_opt_t(out_opt_t&&) = delete;
         out_opt_t& operator=(const out_opt_t&) = delete;
         out_opt_t& operator=(out_opt_t&&) = delete;

         [[nodiscard]] constexpr operator T*() && noexcept { return &m_raw; }

      private:
         std::optional<T>& m_opt;
         T m_raw;
   };

   return out_opt_t{outopt};
}

}  // namespace Botan

#endif
