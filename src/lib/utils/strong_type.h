/**
 * A wrapper class to implement strong types
 * (C) 2022 Jack Lloyd
 *     2022 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_STRONG_TYPE_H_
#define BOTAN_STRONG_TYPE_H_

#include <ostream>
#include <span>

#include <botan/concepts.h>

namespace Botan {

/**
 * Added as an additional "capability tag" to enable arithmetic operators with
 * plain numbers for Strong<> types that wrap a number.
 */
struct EnableArithmeticWithPlainNumber {};

namespace detail {

/**
 * Checks whether the @p CapabilityT is included in the @p Tags type pack.
 */
template <typename CapabilityT, typename... Tags>
constexpr bool has_capability = (std::is_same_v<CapabilityT, Tags> || ...);

template <typename T>
class Strong_Base {
   private:
      T m_value;

   public:
      using wrapped_type = T;

   public:
      Strong_Base() = default;
      Strong_Base(const Strong_Base&) = default;
      Strong_Base(Strong_Base&&) noexcept = default;
      Strong_Base& operator=(const Strong_Base&) = default;
      Strong_Base& operator=(Strong_Base&&) noexcept = default;

      constexpr explicit Strong_Base(T v) : m_value(std::move(v)) {}

      constexpr T& get() & { return m_value; }

      constexpr const T& get() const& { return m_value; }

      constexpr T&& get() && { return std::move(m_value); }

      constexpr const T&& get() const&& { return std::move(m_value); }
};

template <typename T>
class Strong_Adapter : public Strong_Base<T> {
   public:
      using Strong_Base<T>::Strong_Base;
};

template <std::integral T>
class Strong_Adapter<T> : public Strong_Base<T> {
   public:
      using Strong_Base<T>::Strong_Base;
};

template <concepts::container T>
class Container_Strong_Adapter_Base : public Strong_Base<T> {
   public:
      using value_type = typename T::value_type;
      using size_type = typename T::size_type;
      using iterator = typename T::iterator;
      using const_iterator = typename T::const_iterator;

   public:
      using Strong_Base<T>::Strong_Base;

      explicit Container_Strong_Adapter_Base(size_t size)
         requires(concepts::resizable_container<T>)
            : Container_Strong_Adapter_Base(T(size)) {}

      template <typename InputIt>
      Container_Strong_Adapter_Base(InputIt begin, InputIt end) : Container_Strong_Adapter_Base(T(begin, end)) {}

   public:
      decltype(auto) begin() noexcept(noexcept(this->get().begin())) { return this->get().begin(); }

      decltype(auto) begin() const noexcept(noexcept(this->get().begin())) { return this->get().begin(); }

      decltype(auto) end() noexcept(noexcept(this->get().end())) { return this->get().end(); }

      decltype(auto) end() const noexcept(noexcept(this->get().end())) { return this->get().end(); }

      decltype(auto) cbegin() noexcept(noexcept(this->get().cbegin())) { return this->get().cbegin(); }

      decltype(auto) cbegin() const noexcept(noexcept(this->get().cbegin())) { return this->get().cbegin(); }

      decltype(auto) cend() noexcept(noexcept(this->get().cend())) { return this->get().cend(); }

      decltype(auto) cend() const noexcept(noexcept(this->get().cend())) { return this->get().cend(); }

      size_type size() const noexcept(noexcept(this->get().size())) { return this->get().size(); }

      bool empty() const noexcept(noexcept(this->get().empty()))
         requires(concepts::has_empty<T>)
      {
         return this->get().empty();
      }

      void resize(size_type size) noexcept(noexcept(this->get().resize(size)))
         requires(concepts::resizable_container<T>)
      {
         this->get().resize(size);
      }

      void reserve(size_type size) noexcept(noexcept(this->get().reserve(size)))
         requires(concepts::reservable_container<T>)
      {
         this->get().reserve(size);
      }

      template <typename U>
      decltype(auto) operator[](U&& i) const noexcept(noexcept(this->get().operator[](i))) {
         return this->get()[std::forward<U>(i)];
      }

      template <typename U>
      decltype(auto) operator[](U&& i) noexcept(noexcept(this->get().operator[](i))) {
         return this->get()[std::forward<U>(i)];
      }

      template <typename U>
      decltype(auto) at(U&& i) const noexcept(noexcept(this->get().at(i)))
         requires(concepts::has_bounds_checked_accessors<T>)
      {
         return this->get().at(std::forward<U>(i));
      }

      template <typename U>
      decltype(auto) at(U&& i) noexcept(noexcept(this->get().at(i)))
         requires(concepts::has_bounds_checked_accessors<T>)
      {
         return this->get().at(std::forward<U>(i));
      }
};

template <concepts::container T>
class Strong_Adapter<T> : public Container_Strong_Adapter_Base<T> {
   public:
      using Container_Strong_Adapter_Base<T>::Container_Strong_Adapter_Base;
};

template <concepts::contiguous_container T>
class Strong_Adapter<T> : public Container_Strong_Adapter_Base<T> {
   public:
      using pointer = typename T::pointer;
      using const_pointer = typename T::const_pointer;

   public:
      using Container_Strong_Adapter_Base<T>::Container_Strong_Adapter_Base;

      explicit Strong_Adapter(std::span<const typename Container_Strong_Adapter_Base<T>::value_type> span) :
            Strong_Adapter(T(span.begin(), span.end())) {}

      // Disambiguates the usage of string literals, otherwise:
      // Strong_Adapter(std::span<>) and Strong_Adapter(const char*)
      // would be ambiguous.
      explicit Strong_Adapter(const char* str)
         requires(std::same_as<T, std::string>)
            : Strong_Adapter(std::string(str)) {}

   public:
      decltype(auto) data() noexcept(noexcept(this->get().data())) { return this->get().data(); }

      decltype(auto) data() const noexcept(noexcept(this->get().data())) { return this->get().data(); }
};

}  // namespace detail

/**
 * Strong types can be used as wrappers around common types to provide
 * compile time semantics. They usually contribute to more maintainable and
 * less error-prone code especially when dealing with function parameters.
 *
 * Internally, this provides adapters so that the wrapping strong type behaves
 * as much as the underlying type as possible and desirable.
 *
 * This implementation was inspired by:
 *   https://stackoverflow.com/a/69030899
 */
template <typename T, typename TagTypeT, typename... Capabilities>
class Strong : public detail::Strong_Adapter<T> {
   public:
      using detail::Strong_Adapter<T>::Strong_Adapter;

      template <typename CapabilityT>
      constexpr static bool has_capability() {
         return (std::is_same_v<CapabilityT, Capabilities> || ...);
      }

   private:
      using Tag = TagTypeT;
};

/**
 * @brief Generically unwraps a strong type to its underlying type.
 *
 * If the provided type is not a strong type, it is returned as is.
 *
 * @note This is meant as a helper for generic code that needs to deal with both
 *       wrapped strong types and bare objects. Use the ordinary `get()` method
 *       if you know that you are dealing with a strong type.
 *
 * @param t  value to be unwrapped
 * @return   the unwrapped value
 */
template <typename T>
[[nodiscard]] constexpr decltype(auto) unwrap_strong_type(T&& t) {
   if constexpr(!concepts::strong_type<std::remove_cvref_t<T>>) {
      // If the parameter type isn't a strong type, return it as is.
      return std::forward<T>(t);
   } else {
      // Unwrap the strong type and return the underlying value.
      return std::forward<T>(t).get();
   }
}

/**
 * @brief Wraps a value into a caller-defined (strong) type.
 *
 * If the provided object @p t is already of type @p T, it is returned as is.
 *
 * @note This is meant as a helper for generic code that needs to deal with both
 *       wrapped strong types and bare objects. Use the ordinary constructor if
 *       you know that you are dealing with a bare value type.
 *
 * @param t  value to be wrapped
 * @return   the wrapped value
 */
template <typename T, typename ParamT>
   requires std::constructible_from<T, ParamT> ||
            (concepts::strong_type<T> && std::constructible_from<typename T::wrapped_type, ParamT>)
[[nodiscard]] constexpr decltype(auto) wrap_strong_type(ParamT&& t) {
   if constexpr(std::same_as<std::remove_cvref_t<ParamT>, T>) {
      // Noop, if the parameter type already is the desired return type.
      return std::forward<ParamT>(t);
   } else if constexpr(std::constructible_from<T, ParamT>) {
      // Implicit conversion from the parameter type to the return type.
      return T{std::forward<ParamT>(t)};
   } else {
      // Explicitly calling the wrapped type's constructor to support
      // implicit conversions on types that mark their constructors as explicit.
      static_assert(concepts::strong_type<T> && std::constructible_from<typename T::wrapped_type, ParamT>);
      return T{typename T::wrapped_type{std::forward<ParamT>(t)}};
   }
}

namespace detail {

template <typename T>
struct wrapped_type_helper {
      using type = T;
};

template <concepts::strong_type T>
struct wrapped_type_helper<T> {
      using type = typename T::wrapped_type;
};

}  // namespace detail

/**
 * @brief Extracts the wrapped type from a strong type.
 *
 * If the provided type is not a strong type, it is returned as is.
 *
 * @note This is meant as a helper for generic code that needs to deal with both
 *       wrapped strong types and bare objects. Use the ordinary `::wrapped_type`
 *       declaration if you know that you are dealing with a strong type.
 */
template <typename T>
using strong_type_wrapped_type = typename detail::wrapped_type_helper<std::remove_cvref_t<T>>::type;

template <typename T, typename... Tags>
   requires(concepts::streamable<T>)
decltype(auto) operator<<(std::ostream& os, const Strong<T, Tags...>& v) {
   return os << v.get();
}

template <typename T, typename... Tags>
   requires(std::equality_comparable<T>)
bool operator==(const Strong<T, Tags...>& lhs, const Strong<T, Tags...>& rhs) {
   return lhs.get() == rhs.get();
}

template <typename T, typename... Tags>
   requires(std::three_way_comparable<T>)
auto operator<=>(const Strong<T, Tags...>& lhs, const Strong<T, Tags...>& rhs) {
   return lhs.get() <=> rhs.get();
}

template <std::integral T1, std::integral T2, typename... Tags>
auto operator<=>(T1 a, Strong<T2, Tags...> b) {
   return a <=> b.get();
}

template <std::integral T1, std::integral T2, typename... Tags>
auto operator<=>(Strong<T1, Tags...> a, T2 b) {
   return a.get() <=> b;
}

template <std::integral T1, std::integral T2, typename... Tags>
auto operator==(T1 a, Strong<T2, Tags...> b) {
   return a == b.get();
}

template <std::integral T1, std::integral T2, typename... Tags>
auto operator==(Strong<T1, Tags...> a, T2 b) {
   return a.get() == b;
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator+(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a + b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator+(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() + b);
}

template <std::integral T, typename... Tags>
constexpr decltype(auto) operator+(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() + b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator-(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a - b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator-(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() - b);
}

template <std::integral T, typename... Tags>
constexpr decltype(auto) operator-(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() - b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator*(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a * b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator*(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() * b);
}

template <std::integral T, typename... Tags>
constexpr decltype(auto) operator*(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() * b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator/(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a / b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator/(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() / b);
}

template <std::integral T, typename... Tags>
constexpr decltype(auto) operator/(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() / b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator^(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a ^ b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator^(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() ^ b);
}

template <std::integral T, typename... Tags>
constexpr decltype(auto) operator^(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() ^ b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator&(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a & b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator&(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() & b);
}

template <std::integral T, typename... Tags>
constexpr decltype(auto) operator&(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() & b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator|(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a | b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator|(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() | b);
}

template <std::integral T, typename... Tags>
constexpr decltype(auto) operator|(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() | b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator>>(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a >> b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator>>(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() >> b);
}

template <std::integral T, typename... Tags>
constexpr decltype(auto) operator>>(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() >> b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator<<(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a << b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator<<(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() << b);
}

template <std::integral T, typename... Tags>
constexpr decltype(auto) operator<<(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() << b.get());
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator+=(Strong<T1, Tags...>& a, T2 b) {
   a.get() += b;
   return a;
}

template <std::integral T, typename... Tags>
constexpr auto operator+=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() += b.get();
   return a;
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator-=(Strong<T1, Tags...>& a, T2 b) {
   a.get() -= b;
   return a;
}

template <std::integral T, typename... Tags>
constexpr auto operator-=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() -= b.get();
   return a;
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator*=(Strong<T1, Tags...>& a, T2 b) {
   a.get() *= b;
   return a;
}

template <std::integral T, typename... Tags>
constexpr auto operator*=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() *= b.get();
   return a;
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator/=(Strong<T1, Tags...>& a, T2 b) {
   a.get() /= b;
   return a;
}

template <std::integral T, typename... Tags>
constexpr auto operator/=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() /= b.get();
   return a;
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator^=(Strong<T1, Tags...>& a, T2 b) {
   a.get() ^= b;
   return a;
}

template <std::integral T, typename... Tags>
constexpr auto operator^=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() ^= b.get();
   return a;
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator&=(Strong<T1, Tags...>& a, T2 b) {
   a.get() &= b;
   return a;
}

template <std::integral T, typename... Tags>
constexpr auto operator&=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() &= b.get();
   return a;
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator|=(Strong<T1, Tags...>& a, T2 b) {
   a.get() |= b;
   return a;
}

template <std::integral T, typename... Tags>
constexpr auto operator|=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() |= b.get();
   return a;
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator>>=(Strong<T1, Tags...>& a, T2 b) {
   a.get() >>= b;
   return a;
}

template <std::integral T, typename... Tags>
constexpr auto operator>>=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() >>= b.get();
   return a;
}

template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator<<=(Strong<T1, Tags...>& a, T2 b) {
   a.get() <<= b;
   return a;
}

template <std::integral T, typename... Tags>
constexpr auto operator<<=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() <<= b.get();
   return a;
}

template <std::integral T, typename... Tags>
constexpr auto operator++(Strong<T, Tags...>& a, int) {
   auto tmp = a;
   ++a.get();
   return tmp;
}

template <std::integral T, typename... Tags>
constexpr auto operator++(Strong<T, Tags...>& a) {
   ++a.get();
   return a;
}

template <std::integral T, typename... Tags>
constexpr auto operator--(Strong<T, Tags...>& a, int) {
   auto tmp = a;
   --a.get();
   return tmp;
}

template <std::integral T, typename... Tags>
constexpr auto operator--(Strong<T, Tags...>& a) {
   --a.get();
   return a;
}

/**
 * This mimmicks a std::span but keeps track of the strong-type information. Use
 * this when you would want to use `const Strong<...>&` as a parameter
 * declaration. In particular this allows assigning strong-type information to
 * slices of a bigger buffer without copying the bytes. E.g:
 *
 *    using Foo = Strong<std::vector<uint8_t>, Foo_>;
 *
 *    void bar(StrongSpan<Foo> foo) { ... }
 *
 *    std::vector<uint8_t> buffer;
 *    BufferSlicer slicer(buffer);
 *    bar(slicer.take<Foo>());  // This does not copy the data from buffer but
 *                              // just annotates the 'Foo' strong-type info.
 */
template <concepts::contiguous_strong_type T>
class StrongSpan {
      using underlying_span = std::
         conditional_t<std::is_const_v<T>, std::span<const typename T::value_type>, std::span<typename T::value_type>>;

   public:
      using value_type = typename underlying_span::value_type;
      using size_type = typename underlying_span::size_type;
      using iterator = typename underlying_span::iterator;
      using pointer = typename underlying_span::pointer;
      using const_pointer = typename underlying_span::const_pointer;

      StrongSpan() = default;

      explicit StrongSpan(underlying_span span) : m_span(span) {}

      StrongSpan(T& strong) : m_span(strong) {}

      // Allows implicit conversion from `StrongSpan<T>` to `StrongSpan<const T>`.
      // Note that this is not bi-directional. Conversion from `StrongSpan<const T>`
      // to `StrongSpan<T>` is not allowed.
      //
      // TODO: Technically, we should be able to phrase this with a `requires std::is_const_v<T>`
      //       instead of the `std::enable_if` constructions. clang-tidy (14 or 15) doesn't seem
      //       to pick up on that (yet?). As a result, for a non-const T it assumes this to be
      //       a declaration of an ordinary copy constructor. The existance of a copy constructor
      //       is interpreted as "not cheap to copy", setting off the `performance-unnecessary-value-param` check.
      //       See also: https://github.com/randombit/botan/issues/3591
      template <concepts::contiguous_strong_type T2,
                typename = std::enable_if_t<std::is_same_v<T2, std::remove_const_t<T>>>>
      StrongSpan(const StrongSpan<T2>& other) : m_span(other.get()) {}

      StrongSpan(const StrongSpan& other) = default;

      ~StrongSpan() = default;

      /**
       * @returns the underlying std::span without any type constraints
       */
      underlying_span get() const { return m_span; }

      /**
       * @returns the underlying std::span without any type constraints
       */
      underlying_span get() { return m_span; }

      decltype(auto) data() noexcept(noexcept(this->m_span.data())) { return this->m_span.data(); }

      decltype(auto) data() const noexcept(noexcept(this->m_span.data())) { return this->m_span.data(); }

      decltype(auto) size() const noexcept(noexcept(this->m_span.size())) { return this->m_span.size(); }

      bool empty() const noexcept(noexcept(this->m_span.empty())) { return this->m_span.empty(); }

      decltype(auto) begin() noexcept(noexcept(this->m_span.begin())) { return this->m_span.begin(); }

      decltype(auto) begin() const noexcept(noexcept(this->m_span.begin())) { return this->m_span.begin(); }

      decltype(auto) end() noexcept(noexcept(this->m_span.end())) { return this->m_span.end(); }

      decltype(auto) end() const noexcept(noexcept(this->m_span.end())) { return this->m_span.end(); }

      decltype(auto) operator[](typename underlying_span::size_type i) const noexcept { return this->m_span[i]; }

   private:
      underlying_span m_span;
};

template <typename>
struct is_strong_span : std::false_type {};

template <typename T>
struct is_strong_span<StrongSpan<T>> : std::true_type {};

template <typename T>
constexpr bool is_strong_span_v = is_strong_span<T>::value;

}  // namespace Botan

#endif
