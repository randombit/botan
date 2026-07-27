/**
 * A wrapper class to implement strong types
 * (C) 2022 Jack Lloyd
 *     2022 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_STRONG_TYPE_H_
#define BOTAN_STRONG_TYPE_H_

#include <botan/concepts.h>
#include <iosfwd>
#include <span>
#include <string>

namespace Botan {

template <typename T, typename Tag, typename... Capabilities>
class Strong;

/**
 * Trait that detects whether the given types are a Strong<> instantiation
 */
template <typename... Ts>
struct is_strong_type : std::false_type {};

/// @copydoc is_strong_type
template <typename... Ts>
struct is_strong_type<Strong<Ts...>> : std::true_type {};

template <typename... Ts>
constexpr bool is_strong_type_v = is_strong_type<std::remove_const_t<Ts>...>::value;

namespace concepts {

template <typename T>
concept streamable = requires(std::ostream& os, T a) { os << a; };

template <class T>
concept strong_type = is_strong_type_v<T>;

template <class T>
concept contiguous_strong_type = strong_type<T> && contiguous_container<T>;

template <class T>
concept integral_strong_type = strong_type<T> && std::integral<typename T::wrapped_type>;

template <class T>
concept unsigned_integral_strong_type = strong_type<T> && std::unsigned_integral<typename T::wrapped_type>;

template <typename T, typename Capability>
concept strong_type_with_capability = T::template has_capability<Capability>();

}  // namespace concepts

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

/**
 * Storage for the wrapped value of a strong type, and access to it via get()
 */
template <typename T>
class Strong_Base {
   private:
      T m_value;

   public:
      /// The type wrapped by this strong type
      using wrapped_type = T;

   public:
      /// Default constructor, value initializes the wrapped value
      Strong_Base() = default;

      /// Copy constructor
      Strong_Base(const Strong_Base&) = default;

      /// Move constructor
      Strong_Base(Strong_Base&&) noexcept = default;

      /// Copy assignment
      /// @return reference to this
      Strong_Base& operator=(const Strong_Base&) = default;

      /// Move assignment
      /// @return reference to this
      Strong_Base& operator=(Strong_Base&&) noexcept = default;

      ~Strong_Base() = default;

      /// Wrap the given value
      /// @param v the value to wrap
      constexpr explicit Strong_Base(T v) : m_value(std::move(v)) {}

      /// Access the wrapped value
      /// @return reference to the wrapped value
      constexpr T& get() & { return m_value; }

      /// Access the wrapped value
      /// @return const reference to the wrapped value
      constexpr const T& get() const& { return m_value; }

      /// Access the wrapped value
      /// @return rvalue reference to the wrapped value
      constexpr T&& get() && { return std::move(m_value); }

      /// Access the wrapped value
      /// @return const rvalue reference to the wrapped value
      constexpr const T&& get() const&& { return std::move(m_value); }
};

/**
 * Adds functionality to Strong_Base depending on the wrapped type
 *
 * The primary template adds nothing; the specializations below expose
 * container and contiguous container operations where applicable.
 */
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

/**
 * Forwards the container interface of the wrapped type
 */
template <concepts::container T>
class Container_Strong_Adapter_Base : public Strong_Base<T> {
   public:
      /// The element type of the wrapped container
      using value_type = typename T::value_type;

      /// The size type of the wrapped container
      using size_type = typename T::size_type;

      /// The iterator type of the wrapped container
      using iterator = typename T::iterator;

      /// The const iterator type of the wrapped container
      using const_iterator = typename T::const_iterator;

   public:
      using Strong_Base<T>::Strong_Base;

      /// Create a container holding the given number of default constructed elements
      /// @param size the number of elements
      explicit Container_Strong_Adapter_Base(size_t size)
         requires(concepts::resizable_container<T>)
            : Container_Strong_Adapter_Base(T(size)) {}

      /// Create a container from the elements of an iterator range
      /// @param begin start of the range
      /// @param end one past the end of the range
      template <typename InputIt>
      Container_Strong_Adapter_Base(InputIt begin, InputIt end) : Container_Strong_Adapter_Base(T(begin, end)) {}

   public:
      /// Iterate the wrapped container
      /// @return an iterator to the first element
      decltype(auto) begin() noexcept(noexcept(this->get().begin())) { return this->get().begin(); }

      /// Iterate the wrapped container
      /// @return a const iterator to the first element
      decltype(auto) begin() const noexcept(noexcept(this->get().begin())) { return this->get().begin(); }

      /// Iterate the wrapped container
      /// @return an iterator one past the last element
      decltype(auto) end() noexcept(noexcept(this->get().end())) { return this->get().end(); }

      /// Iterate the wrapped container
      /// @return a const iterator one past the last element
      decltype(auto) end() const noexcept(noexcept(this->get().end())) { return this->get().end(); }

      /// Iterate the wrapped container
      /// @return a const iterator to the first element
      decltype(auto) cbegin() noexcept(noexcept(this->get().cbegin())) { return this->get().cbegin(); }

      /// Iterate the wrapped container
      /// @return a const iterator to the first element
      decltype(auto) cbegin() const noexcept(noexcept(this->get().cbegin())) { return this->get().cbegin(); }

      /// Iterate the wrapped container
      /// @return a const iterator one past the last element
      decltype(auto) cend() noexcept(noexcept(this->get().cend())) { return this->get().cend(); }

      /// Iterate the wrapped container
      /// @return a const iterator one past the last element
      decltype(auto) cend() const noexcept(noexcept(this->get().cend())) { return this->get().cend(); }

      /// Query the size of the wrapped container
      /// @return the number of elements
      size_type size() const noexcept(noexcept(this->get().size())) { return this->get().size(); }

      /// Query whether the wrapped container is empty
      /// @return true if the container holds no elements
      bool empty() const noexcept(noexcept(this->get().empty()))
         requires(concepts::has_empty<T>)
      {
         return this->get().empty();
      }

      /// Change the number of elements held
      /// @param size the new number of elements
      void resize(size_type size) noexcept(noexcept(this->get().resize(size)))
         requires(concepts::resizable_container<T>)
      {
         this->get().resize(size);
      }

      /// Preallocate storage for the given number of elements
      /// @param size the number of elements to reserve capacity for
      void reserve(size_type size) noexcept(noexcept(this->get().reserve(size)))
         requires(concepts::reservable_container<T>)
      {
         this->get().reserve(size);
      }

      /// Element access
      /// @param i the index of the element
      /// @return const reference to the element at index i
      template <typename U>
      decltype(auto) operator[](U&& i) const noexcept(noexcept(this->get().operator[](i))) {
         return this->get()[std::forward<U>(i)];
      }

      /// Element access
      /// @param i the index of the element
      /// @return reference to the element at index i
      template <typename U>
      decltype(auto) operator[](U&& i) noexcept(noexcept(this->get().operator[](i))) {
         return this->get()[std::forward<U>(i)];
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
class Strong final : public detail::Strong_Adapter<T> {
   public:
      using detail::Strong_Adapter<T>::Strong_Adapter;

      /**
      * Check whether this strong type was declared with the given capability tag
      * @return true if CapabilityT is one of this type's Capabilities
      */
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

/**
 * Resolves to the type wrapped by a strong type, or to T itself if T is
 * not a strong type
 */
template <typename T>
struct wrapped_type_helper {
      /// The resolved type
      using type = T;
};

/// @copydoc wrapped_type_helper
template <concepts::strong_type T>
struct wrapped_type_helper<T> {
      /// The resolved type
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

/**
 * Write the wrapped value to an output stream
 * @param os the output stream
 * @param v the strong type to write
 * @return reference to the output stream
 */
template <typename T, typename... Tags>
   requires(concepts::streamable<T>)
decltype(auto) operator<<(std::ostream& os, const Strong<T, Tags...>& v) {
   return os << v.get();
}

/**
 * Compare for equality
 * @param lhs the first operand (strong type)
 * @param rhs the second operand (strong type)
 * @return true if lhs and rhs are equal
 */
template <typename T, typename... Tags>
   requires(std::equality_comparable<T>)
bool operator==(const Strong<T, Tags...>& lhs, const Strong<T, Tags...>& rhs) {
   return lhs.get() == rhs.get();
}

/**
 * Three-way comparison
 * @param lhs the first operand (strong type)
 * @param rhs the second operand (strong type)
 * @return the ordering of lhs relative to rhs
 */
template <typename T, typename... Tags>
   requires(std::three_way_comparable<T>)
auto operator<=>(const Strong<T, Tags...>& lhs, const Strong<T, Tags...>& rhs) {
   return lhs.get() <=> rhs.get();
}

/**
 * Three-way comparison
 * @param a the first operand (plain number)
 * @param b the second operand (strong type)
 * @return the ordering of a relative to b
 */
template <std::integral T1, std::integral T2, typename... Tags>
auto operator<=>(T1 a, Strong<T2, Tags...> b) {
   return a <=> b.get();
}

/**
 * Three-way comparison
 * @param a the first operand (strong type)
 * @param b the second operand (plain number)
 * @return the ordering of a relative to b
 */
template <std::integral T1, std::integral T2, typename... Tags>
auto operator<=>(Strong<T1, Tags...> a, T2 b) {
   return a.get() <=> b;
}

/**
 * Compare for equality
 * @param a the first operand (plain number)
 * @param b the second operand (strong type)
 * @return true if a and b are equal
 */
template <std::integral T1, std::integral T2, typename... Tags>
auto operator==(T1 a, Strong<T2, Tags...> b) {
   return a == b.get();
}

/**
 * Compare for equality
 * @param a the first operand (strong type)
 * @param b the second operand (plain number)
 * @return true if a and b are equal
 */
template <std::integral T1, std::integral T2, typename... Tags>
auto operator==(Strong<T1, Tags...> a, T2 b) {
   return a.get() == b;
}

/**
 * Add the wrapped values
 * @param a the left hand operand (plain number)
 * @param b the right hand operand (strong type)
 * @return the result, wrapped in the strong type
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator+(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a + b.get());
}

/**
 * Add the wrapped values
 * @param a the left hand operand (strong type)
 * @param b the right hand operand (plain number)
 * @return the result, wrapped in the strong type
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator+(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() + b);
}

/**
 * Add the wrapped values
 * @param a the left hand operand (strong type)
 * @param b the right hand operand (strong type)
 * @return the result, wrapped in the strong type
 */
template <std::integral T, typename... Tags>
constexpr decltype(auto) operator+(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() + b.get());
}

/**
 * Subtract the wrapped values
 * @param a the left hand operand (plain number)
 * @param b the right hand operand (strong type)
 * @return the result, wrapped in the strong type
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator-(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a - b.get());
}

/**
 * Subtract the wrapped values
 * @param a the left hand operand (strong type)
 * @param b the right hand operand (plain number)
 * @return the result, wrapped in the strong type
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator-(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() - b);
}

/**
 * Subtract the wrapped values
 * @param a the left hand operand (strong type)
 * @param b the right hand operand (strong type)
 * @return the result, wrapped in the strong type
 */
template <std::integral T, typename... Tags>
constexpr decltype(auto) operator-(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() - b.get());
}

/**
 * Multiply the wrapped values
 * @param a the left hand operand (plain number)
 * @param b the right hand operand (strong type)
 * @return the result, wrapped in the strong type
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator*(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a * b.get());
}

/**
 * Multiply the wrapped values
 * @param a the left hand operand (strong type)
 * @param b the right hand operand (plain number)
 * @return the result, wrapped in the strong type
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator*(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() * b);
}

/**
 * Multiply the wrapped values
 * @param a the left hand operand (strong type)
 * @param b the right hand operand (strong type)
 * @return the result, wrapped in the strong type
 */
template <std::integral T, typename... Tags>
constexpr decltype(auto) operator*(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() * b.get());
}

/**
 * Divide the wrapped values
 * @param a the left hand operand (plain number)
 * @param b the right hand operand (strong type)
 * @return the result, wrapped in the strong type
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator/(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a / b.get());
}

/**
 * Divide the wrapped values
 * @param a the left hand operand (strong type)
 * @param b the right hand operand (plain number)
 * @return the result, wrapped in the strong type
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator/(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() / b);
}

/**
 * Divide the wrapped values
 * @param a the left hand operand (strong type)
 * @param b the right hand operand (strong type)
 * @return the result, wrapped in the strong type
 */
template <std::integral T, typename... Tags>
constexpr decltype(auto) operator/(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() / b.get());
}

/**
 * Bitwise XOR of the wrapped values
 * @param a the left hand operand (plain number)
 * @param b the right hand operand (strong type)
 * @return the result, wrapped in the strong type
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator^(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a ^ b.get());
}

/**
 * Bitwise XOR of the wrapped values
 * @param a the left hand operand (strong type)
 * @param b the right hand operand (plain number)
 * @return the result, wrapped in the strong type
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator^(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() ^ b);
}

/**
 * Bitwise XOR of the wrapped values
 * @param a the left hand operand (strong type)
 * @param b the right hand operand (strong type)
 * @return the result, wrapped in the strong type
 */
template <std::integral T, typename... Tags>
constexpr decltype(auto) operator^(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() ^ b.get());
}

/**
 * Bitwise AND of the wrapped values
 * @param a the left hand operand (plain number)
 * @param b the right hand operand (strong type)
 * @return the result, wrapped in the strong type
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator&(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a & b.get());
}

/**
 * Bitwise AND of the wrapped values
 * @param a the left hand operand (strong type)
 * @param b the right hand operand (plain number)
 * @return the result, wrapped in the strong type
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator&(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() & b);
}

/**
 * Bitwise AND of the wrapped values
 * @param a the left hand operand (strong type)
 * @param b the right hand operand (strong type)
 * @return the result, wrapped in the strong type
 */
template <std::integral T, typename... Tags>
constexpr decltype(auto) operator&(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() & b.get());
}

/**
 * Bitwise OR of the wrapped values
 * @param a the left hand operand (plain number)
 * @param b the right hand operand (strong type)
 * @return the result, wrapped in the strong type
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator|(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a | b.get());
}

/**
 * Bitwise OR of the wrapped values
 * @param a the left hand operand (strong type)
 * @param b the right hand operand (plain number)
 * @return the result, wrapped in the strong type
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator|(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() | b);
}

/**
 * Bitwise OR of the wrapped values
 * @param a the left hand operand (strong type)
 * @param b the right hand operand (strong type)
 * @return the result, wrapped in the strong type
 */
template <std::integral T, typename... Tags>
constexpr decltype(auto) operator|(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() | b.get());
}

/**
 * Right shift the wrapped values
 * @param a the left hand operand (plain number)
 * @param b the right hand operand (strong type)
 * @return the result, wrapped in the strong type
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator>>(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a >> b.get());
}

/**
 * Right shift the wrapped values
 * @param a the left hand operand (strong type)
 * @param b the right hand operand (plain number)
 * @return the result, wrapped in the strong type
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator>>(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() >> b);
}

/**
 * Right shift the wrapped values
 * @param a the left hand operand (strong type)
 * @param b the right hand operand (strong type)
 * @return the result, wrapped in the strong type
 */
template <std::integral T, typename... Tags>
constexpr decltype(auto) operator>>(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() >> b.get());
}

/**
 * Left shift the wrapped values
 * @param a the left hand operand (plain number)
 * @param b the right hand operand (strong type)
 * @return the result, wrapped in the strong type
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator<<(T1 a, Strong<T2, Tags...> b) {
   return Strong<T2, Tags...>(a << b.get());
}

/**
 * Left shift the wrapped values
 * @param a the left hand operand (strong type)
 * @param b the right hand operand (plain number)
 * @return the result, wrapped in the strong type
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr decltype(auto) operator<<(Strong<T1, Tags...> a, T2 b) {
   return Strong<T1, Tags...>(a.get() << b);
}

/**
 * Left shift the wrapped values
 * @param a the left hand operand (strong type)
 * @param b the right hand operand (strong type)
 * @return the result, wrapped in the strong type
 */
template <std::integral T, typename... Tags>
constexpr decltype(auto) operator<<(Strong<T, Tags...> a, Strong<T, Tags...> b) {
   return Strong<T, Tags...>(a.get() << b.get());
}

/**
 * Add to the wrapped value
 * @param a the strong type to modify
 * @param b the right hand operand (plain number)
 * @return reference to a
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator+=(Strong<T1, Tags...>& a, T2 b) {
   a.get() += b;
   return a;
}

/**
 * Add to the wrapped value
 * @param a the strong type to modify
 * @param b the right hand operand (strong type)
 * @return reference to a
 */
template <std::integral T, typename... Tags>
constexpr auto operator+=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() += b.get();
   return a;
}

/**
 * Subtract from the wrapped value
 * @param a the strong type to modify
 * @param b the right hand operand (plain number)
 * @return reference to a
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator-=(Strong<T1, Tags...>& a, T2 b) {
   a.get() -= b;
   return a;
}

/**
 * Subtract from the wrapped value
 * @param a the strong type to modify
 * @param b the right hand operand (strong type)
 * @return reference to a
 */
template <std::integral T, typename... Tags>
constexpr auto operator-=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() -= b.get();
   return a;
}

/**
 * Multiply in place the wrapped value
 * @param a the strong type to modify
 * @param b the right hand operand (plain number)
 * @return reference to a
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator*=(Strong<T1, Tags...>& a, T2 b) {
   a.get() *= b;
   return a;
}

/**
 * Multiply in place the wrapped value
 * @param a the strong type to modify
 * @param b the right hand operand (strong type)
 * @return reference to a
 */
template <std::integral T, typename... Tags>
constexpr auto operator*=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() *= b.get();
   return a;
}

/**
 * Divide in place the wrapped value
 * @param a the strong type to modify
 * @param b the right hand operand (plain number)
 * @return reference to a
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator/=(Strong<T1, Tags...>& a, T2 b) {
   a.get() /= b;
   return a;
}

/**
 * Divide in place the wrapped value
 * @param a the strong type to modify
 * @param b the right hand operand (strong type)
 * @return reference to a
 */
template <std::integral T, typename... Tags>
constexpr auto operator/=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() /= b.get();
   return a;
}

/**
 * Bitwise XOR in place the wrapped value
 * @param a the strong type to modify
 * @param b the right hand operand (plain number)
 * @return reference to a
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator^=(Strong<T1, Tags...>& a, T2 b) {
   a.get() ^= b;
   return a;
}

/**
 * Bitwise XOR in place the wrapped value
 * @param a the strong type to modify
 * @param b the right hand operand (strong type)
 * @return reference to a
 */
template <std::integral T, typename... Tags>
constexpr auto operator^=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() ^= b.get();
   return a;
}

/**
 * Bitwise AND in place the wrapped value
 * @param a the strong type to modify
 * @param b the right hand operand (plain number)
 * @return reference to a
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator&=(Strong<T1, Tags...>& a, T2 b) {
   a.get() &= b;
   return a;
}

/**
 * Bitwise AND in place the wrapped value
 * @param a the strong type to modify
 * @param b the right hand operand (strong type)
 * @return reference to a
 */
template <std::integral T, typename... Tags>
constexpr auto operator&=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() &= b.get();
   return a;
}

/**
 * Bitwise OR in place the wrapped value
 * @param a the strong type to modify
 * @param b the right hand operand (plain number)
 * @return reference to a
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator|=(Strong<T1, Tags...>& a, T2 b) {
   a.get() |= b;
   return a;
}

/**
 * Bitwise OR in place the wrapped value
 * @param a the strong type to modify
 * @param b the right hand operand (strong type)
 * @return reference to a
 */
template <std::integral T, typename... Tags>
constexpr auto operator|=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() |= b.get();
   return a;
}

/**
 * Right shift in place the wrapped value
 * @param a the strong type to modify
 * @param b the right hand operand (plain number)
 * @return reference to a
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator>>=(Strong<T1, Tags...>& a, T2 b) {
   a.get() >>= b;
   return a;
}

/**
 * Right shift in place the wrapped value
 * @param a the strong type to modify
 * @param b the right hand operand (strong type)
 * @return reference to a
 */
template <std::integral T, typename... Tags>
constexpr auto operator>>=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() >>= b.get();
   return a;
}

/**
 * Left shift in place the wrapped value
 * @param a the strong type to modify
 * @param b the right hand operand (plain number)
 * @return reference to a
 */
template <std::integral T1, std::integral T2, typename... Tags>
   requires(detail::has_capability<EnableArithmeticWithPlainNumber, Tags...>)
constexpr auto operator<<=(Strong<T1, Tags...>& a, T2 b) {
   a.get() <<= b;
   return a;
}

/**
 * Left shift in place the wrapped value
 * @param a the strong type to modify
 * @param b the right hand operand (strong type)
 * @return reference to a
 */
template <std::integral T, typename... Tags>
constexpr auto operator<<=(Strong<T, Tags...>& a, Strong<T, Tags...> b) {
   a.get() <<= b.get();
   return a;
}

/**
 * Increment the wrapped value (postfix)
 * @param a the strong type to modify
 * @return the value before the operation
 */
template <std::integral T, typename... Tags>
constexpr auto operator++(Strong<T, Tags...>& a, int) {
   auto tmp = a;
   ++a.get();
   return tmp;
}

/**
 * Increment the wrapped value (prefix)
 * @param a the strong type to modify
 * @return the value after the operation
 */
template <std::integral T, typename... Tags>
constexpr auto operator++(Strong<T, Tags...>& a) {
   ++a.get();
   return a;
}

/**
 * Decrement the wrapped value (postfix)
 * @param a the strong type to modify
 * @return the value before the operation
 */
template <std::integral T, typename... Tags>
constexpr auto operator--(Strong<T, Tags...>& a, int) {
   auto tmp = a;
   --a.get();
   return tmp;
}

/**
 * Decrement the wrapped value (prefix)
 * @param a the strong type to modify
 * @return the value after the operation
 */
template <std::integral T, typename... Tags>
constexpr auto operator--(Strong<T, Tags...>& a) {
   --a.get();
   return a;
}

/**
 * This mimics a std::span but keeps track of the strong-type information. Use
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
class StrongSpan final {
      using underlying_span = std::
         conditional_t<std::is_const_v<T>, std::span<const typename T::value_type>, std::span<typename T::value_type>>;

   public:
      /// The element type of the underlying span
      using value_type = typename underlying_span::value_type;

      /// The size type of the underlying span
      using size_type = typename underlying_span::size_type;

      /// The iterator type of the underlying span
      using iterator = typename underlying_span::iterator;

      /// The pointer type of the underlying span
      using pointer = typename underlying_span::pointer;

      /// The const pointer type of the underlying span
      using const_pointer = typename underlying_span::const_pointer;

      /// Default constructor, creates an empty span
      StrongSpan() = default;

      /// Annotate a plain span with this strong type's information
      /// @param span the span to annotate
      explicit StrongSpan(underlying_span span) : m_span(span) {}

      /// Create a span covering the contents of a strong type
      /// @param strong the strong type to view
      // NOLINTNEXTLINE(*-explicit-conversions)
      StrongSpan(T& strong) : m_span(strong) {}

      // Allows implicit conversion from `StrongSpan<T>` to `StrongSpan<const T>`.
      // Note that this is not bi-directional. Conversion from `StrongSpan<const T>`
      // to `StrongSpan<T>` is not allowed.
      //
      // TODO: Technically, we should be able to phrase this with a `requires std::is_const_v<T>`
      //       instead of the `std::enable_if` constructions. clang-tidy (14 or 15) doesn't seem
      //       to pick up on that (yet?). As a result, for a non-const T it assumes this to be
      //       a declaration of an ordinary copy constructor. The existence of a copy constructor
      //       is interpreted as "not cheap to copy", setting off the `performance-unnecessary-value-param` check.
      //       See also: https://github.com/randombit/botan/issues/3591
      /// Convert a StrongSpan<T> to a StrongSpan<const T>
      /// @param other the span to convert
      template <concepts::contiguous_strong_type T2>
      // NOLINTNEXTLINE(*-explicit-conversions)
      StrongSpan(const StrongSpan<T2>& other)
         requires(std::is_same_v<T2, std::remove_const_t<T>>)
            : m_span(other.get()) {}

      /// Copy constructor
      /// @param other the span to copy
      StrongSpan(const StrongSpan& other) = default;

      /// Move constructor
      /// @param other the span to move from
      StrongSpan(StrongSpan&& other) = default;

      /// Copy assignment
      /// @param other the span to copy
      /// @return reference to this
      StrongSpan& operator=(const StrongSpan& other) = default;

      /// Move assignment
      /// @param other the span to move from
      /// @return reference to this
      StrongSpan& operator=(StrongSpan&& other) = default;

      ~StrongSpan() = default;

      /**
       * Access the underlying span
       * @returns the underlying std::span without any type constraints
       */
      underlying_span get() const { return m_span; }

      /**
       * Access the underlying span
       * @returns the underlying std::span without any type constraints
       */
      underlying_span get() { return m_span; }

      /// Access the underlying storage
      /// @return a pointer to the first element
      decltype(auto) data() noexcept(noexcept(this->m_span.data())) { return this->m_span.data(); }

      /// Access the underlying storage
      /// @return a const pointer to the first element
      decltype(auto) data() const noexcept(noexcept(this->m_span.data())) { return this->m_span.data(); }

      /// Query the size of the span
      /// @return the number of elements
      decltype(auto) size() const noexcept(noexcept(this->m_span.size())) { return this->m_span.size(); }

      /// Query whether the span is empty
      /// @return true if the span covers no elements
      bool empty() const noexcept(noexcept(this->m_span.empty())) { return this->m_span.empty(); }

      /// Iterate the span
      /// @return an iterator to the first element
      decltype(auto) begin() noexcept(noexcept(this->m_span.begin())) { return this->m_span.begin(); }

      /// Iterate the span
      /// @return a const iterator to the first element
      decltype(auto) begin() const noexcept(noexcept(this->m_span.begin())) { return this->m_span.begin(); }

      /// Iterate the span
      /// @return an iterator one past the last element
      decltype(auto) end() noexcept(noexcept(this->m_span.end())) { return this->m_span.end(); }

      /// Iterate the span
      /// @return a const iterator one past the last element
      decltype(auto) end() const noexcept(noexcept(this->m_span.end())) { return this->m_span.end(); }

      /// Element access
      /// @param i the index of the element
      /// @return reference to the element at index i
      decltype(auto) operator[](typename underlying_span::size_type i) const noexcept { return this->m_span[i]; }

   private:
      underlying_span m_span;
};

/**
 * Trait that detects whether the given type is a StrongSpan<> instantiation
 */
template <typename>
struct is_strong_span : std::false_type {};

/// @copydoc is_strong_span
template <typename T>
struct is_strong_span<StrongSpan<T>> : std::true_type {};

template <typename T>
constexpr bool is_strong_span_v = is_strong_span<T>::value;

}  // namespace Botan

#endif
