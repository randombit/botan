/*
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_OPTIONS_BUILDER_H_
#define BOTAN_OPTIONS_BUILDER_H_

#include <botan/exceptn.h>
#include <botan/template_utils.h>

#include <numeric>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Botan {

class HashFunction;
class MessageAuthenticationCode;

template <typename T>
class OptionsBuilder;

template <typename T>
class Options;

template <StringLiteral option_name, typename T>
class Option;

namespace detail {

namespace BuilderOptionHelper {

template <typename U>
std::string to_string(const U&) {
   return std::string("<object of type: ") + typeid(U).name() + '>';
}

template <std::convertible_to<std::string_view> U>
std::string to_string(const U& value) {
   return std::string(value);
}

template <typename U>
std::string to_string(const std::optional<U>& value) {
   if(!value.has_value()) {
      return "explicitly not set";
   }
   return to_string(value.value());
}

inline std::string to_string(bool value) {
   return value ? "true" : "false";
}

std::string to_string(const std::unique_ptr<HashFunction>& value);
std::string to_string(const std::unique_ptr<MessageAuthenticationCode>& value);

}  // namespace BuilderOptionHelper

/**
 * Return wrapper of an option value that allows for different ways to consume
 * the value. Downstream code can choose to either require the option to be set
 * or to handle it as an optional value.
 */
template <typename T>
class OptionValue {
   private:
      std::optional<T> take() noexcept { return std::exchange(m_value, {}); }

   public:
      OptionValue(std::optional<T> option, std::string_view option_name, std::string_view product_name) :
            m_value(std::move(option)), m_option_name(option_name), m_product_name(product_name) {}

      /**
       * @returns the option value or std::nullopt if it wasn't set.
       */
      [[nodiscard]] std::optional<T> optional() && noexcept { return take(); }

      /**
       * @throws Invalid_Argument if the option wasn't set.
       * @returns the option value or throws if it wasn't set.
       */
      [[nodiscard]] T required() && {
         if(!m_value.has_value()) {
            throw Invalid_Argument("'" + m_product_name + "' requires the '" + std::string(m_option_name) + "' option");
         }
         return take().value();
      }

      /**
       * @returns the option value or the given @p default_value if it wasn't set.
       */
      template <std::convertible_to<T> U>
      [[nodiscard]] T or_default(U&& default_value) && noexcept {
         return take().value_or(std::forward<U>(default_value));
      }

      /**
       * Consumes the option value and throws if it was set.
       * @throws Not_Implemented if the option was set, with given @p message.
       */
      void not_implemented(std::string_view message) {
         if(take().has_value()) {
            throw Not_Implemented("'" + m_product_name + "' currently does not implement the '" +
                                  std::string(m_option_name) + "' option: " + std::string(message));
         }
      }

   private:
      std::optional<T> m_value;
      std::string_view m_option_name;
      std::string m_product_name;
};

/// Concept to check whether T is a BuilderOption
template <typename T>
struct is_builder_option : std::false_type {};

template <StringLiteral option_name, typename T>
struct is_builder_option<Botan::Option<option_name, T>> : std::true_type {};

template <typename T>
concept BuilderOption = is_builder_option<T>::value;

template <typename T>
concept AllBuilderOptionsTuple =
   requires(const T t) { std::apply([]<BuilderOption... OptionTs>(const OptionTs&...) {}, t); };

template <typename T>
concept OptionsContainer = std::is_default_constructible_v<T> && std::is_move_assignable_v<T> &&
                           std::is_move_constructible_v<T> && requires(const T opts) {
                              { opts.all_options() } -> AllBuilderOptionsTuple;
                           };

template <typename T>
concept ConcreteOptions = OptionsContainer<typename T::Container> &&
                          requires(typename T::Container&& container, std::string_view name) { T(container, name); };

static constexpr auto unknown_product = "Unknown";

}  // namespace detail

/**
 * Wraps a builder option value and provides a way to convert it to a string
 * for debugging and error messages.
 */
template <StringLiteral option_name, typename T>
class Option {
   public:
      constexpr static std::string_view name = option_name.value;
      using value_type = T;

      std::string to_string() const {
         if(!value.has_value()) {
            return "<unset>";
         } else {
            return detail::BuilderOptionHelper::to_string(*value);
         }
      }

   private:
      template <typename OptionsT>
      friend class Botan::OptionsBuilder;

      template <typename OptionsContainerT>
      friend class Options;

      std::optional<T> value;
};

/**
 * Base class for all options builder helper classes.
 *
 * Concrete implementations of builders should derive from this class and
 * pass their concrete implementation of the options consumer as the template,
 * parameter. All available options must be wrapped  in a default-constructible
 * struct of `Option<>` instances that implements the `all_options` method.
 *
 * See the example at the end of this file for a full picture.
 */
template <typename OptionsT>
class OptionsBuilder {
   public:
      static_assert(detail::ConcreteOptions<OptionsT>);
      using Container = typename OptionsT::Container;

   public:
      OptionsT commit() {
         return OptionsT(std::exchange(m_options, {}), std::exchange(m_product_name, detail::unknown_product));
      }

   protected:
      Container& options() { return m_options; }

      template <detail::BuilderOption OptionT, std::convertible_to<typename OptionT::value_type> ValueT>
      void set_or_throw(OptionT& option, ValueT&& value) {
         if(option.value.has_value()) {
            throw Invalid_State("'" + m_product_name + "' already set the '" + std::string(OptionT::name) + "' option");
         }
         option.value.emplace(std::forward<ValueT>(value));
      }

      void with_product_name(std::string name) { m_product_name = std::move(name); }

   private:
      Container m_options;
      std::string m_product_name = detail::unknown_product;
};

/**
 * Base class for all options consumer classes.
 *
 * Concrete implementations of options consumers should derive from this class
 * and pass their concrete implementation of the options container as the
 * template parameter. The options container must implement the `all_options`
 * method that returns a tuple of all available options.
 */
template <typename OptionsContainerT>
class Options {
   public:
      static_assert(detail::OptionsContainer<OptionsContainerT>);
      using Container = OptionsContainerT;

   public:
      Options() = default;

      Options(Container options, std::string_view product_name) :
            m_options(std::move(options)), m_product_name(product_name) {}

      [[nodiscard]] std::string to_string() const {
         std::ostringstream oss;
         foreach_option([&]<detail::BuilderOption OptionT>(const OptionT& option) {
            oss << OptionT::name << ": " << option.to_string() << '\n';
         });
         return oss.str();
      }

      void validate_option_consumption() {
         std::vector<std::string_view> disdained_options;
         foreach_option([&]<detail::BuilderOption OptionT>(const OptionT& option) {
            if(option.value.has_value()) {
               disdained_options.push_back(OptionT::name);
            }
         });

         auto join = [](const std::vector<std::string_view>& v) {
            // C++23: std::format can print ranges out-of-the-box
            return std::accumulate(
               v.begin(), v.end(), std::string{}, [](const std::string& a, std::string_view b) -> std::string {
                  return a.empty() ? std::string(b) : a + ", " + std::string(b);
               });
         };

         if(!disdained_options.empty()) {
            throw Invalid_Argument("'" + m_product_name + "' failed to use some options: " + join(disdained_options));
         }
      }

   protected:
      Container& options() { return m_options; }

      template <detail::BuilderOption OptionT>
      [[nodiscard]] auto take(OptionT& o) noexcept {
         return detail::OptionValue(std::exchange(o.value, {}), OptionT::name, m_product_name);
      }

      template <typename FnT>
      void foreach_option(FnT&& fn) const {
         std::apply([&]<detail::BuilderOption... OptionTs>(const OptionTs&... options) { (fn(options), ...); },
                    m_options.all_options());
      }

   private:
      Container m_options;
      std::string m_product_name = detail::unknown_product;
};

}  // namespace Botan

/**
 * Below is an example that sets up options for a hypothetical KDF.
 * Note that the `with_*` methods are overloaded for lvalue and rvalue refs, to
 * allow for properly chaining the calls.
 *
 * struct KDF_OptionsContainer {
 *   Option<"context", std::string> context;
 *   Option<"label", std::string> label;
 *   Option<"hash", std::unique_ptr<HashFunction>> hash;
 *
 *   auto all_options() { return std::tie(context, label, hash); }
 * };
 *
 * class KDF_Options : public Options<KDF_OptionsContainer> {
 *    public:
 *       using Options::Options;
 *
 *    public:
 *       /// Gets the context value or std::nullopt if it wasn't set
 *       [[nodiscard]] auto context() { return take(options().context); }
 *
 *       /// Gets the label value or a default if it wasn't set
 *       [[nodiscard]] auto label() { return take(options().label); }
 *
 *       /// Gets the hash function or throws if it wasn't set
 *       [[nodiscard]] auto hash() { return take(options().hash); }
 * };
 *
 * // TODO: C++23: Using "deducing-this" we will be able to remove the CRTP and
 * //              remove the overloads for lvalue and rvalue refs.
 *
 * class KDF_Builder : public OptionsBuilder<KDF_Options> {
 *    public:
 *       KDF_Builder& with_context(std::string_view ctx) & {
 *          set_or_throw(options().context, std::string(ctx));
 *          return *this;
 *       }
 *
 *       KDF_Builder with_context(std::string_view ctx) && {
 *          return std::move(with_context(ctx));
 *       }
 *
 *       KDF_Builder& with_label(std::string_view label) & {
 *          set_or_throw(options().label, std::string(label));
 *          return *this;
 *       }
 *
 *       KDF_Builder with_label(std::string_view label) && {
 *          return std::move(with_label(label));
 *       }
 *
 *       KDF_Builder& with_hash(std::string_view hash) & {
 *          set_or_throw(options().hash, Botan::HashFunction::create_or_throw(hash));
 *          return *this;
 *       }
 *
 *       KDF_Builder with_hash(std::string_view hash) && {
 *          return std::move(with_hash(hash));
 *       }
 *
 *       KDF_Builder& with_hash(std::unique_ptr<HashFunction> hash) & {
 *          set_or_throw(options().hash, std::move(hash));
 *          return *this;
 *       }
 *
 *       KDF_Builder with_hash(std::unique_ptr<HashFunction> hash) && {
 *          return std::move(with_hash(std::move(hash)));
 *       }
 *
 *       /// Creates a new KDF instance with the current options and validates
 *       /// that all options have been consumed by the new KDF instance.
 *       KDF create() {
 *          with_product_name("KDF");
 *          auto opts = this->commit();
 *          KDF kdf(opts);
 *          opts.validate_option_consumption();
 *          return kdf;
 *       }
 * };
 */

#endif
