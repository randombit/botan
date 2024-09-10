/*
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BASE_BUILDER_H_
#define BOTAN_BASE_BUILDER_H_

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

template <typename DerivedT>
class Builder;

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
            return BuilderOptionHelper::to_string(*value);
         }
      }

   private:
      // Only the abstract builder may access the wrapped value
      template <typename DerivedT>
      friend class Botan::Builder;

      std::optional<T> value;
};

/// Concept to check whether T is a BuilderOption
template <typename T>
struct is_builder_option : std::false_type {};

template <StringLiteral option_name, typename T>
struct is_builder_option<Option<option_name, T>> : std::true_type {};

template <typename T>
concept BuilderOption = is_builder_option<T>::value;

template <typename... OptionTs>
consteval bool all_builder_options(std::tuple<OptionTs&...>) {
   return (BuilderOption<OptionTs> && ... && true);
}

}  // namespace detail

/**
 * Base class for all builder helper classes
 *
 * Concrete implementations of builders should derive from this class, wrap all
 * its options in `Option` instances and implement the `all_options` method.
 *
 * Below is an example that sets up a hypothetical key derivation function.
 * Note that the `with_*` methods are overloaded for lvalue and rvalue refs, to
 * allow for properly chaining the calls.
 *
 * TODO: C++23: Using "deducing-this" we will be able to remove the CRTP and
 *              remove the overloads for lvalue and rvalue refs.
 *
 * class KDF_Builder : public Builder<KDF_Builder> {
 *    private:
 *       detail::Option<"context", std::string> m_context;
 *       detail::Option<"label", std::string> m_label;
 *       detail::Option<"hash", std::unique_ptr<HashFunction>> m_hash;
 *
 *       friend class Builder<KDF_Builder>;
 *
 *       /// Returns a tuple of all options (needed for the base implementation)
 *       auto all_options() const { return std::tie(m_context, m_hash); }
 *
 *    public:
 *       KDF_Builder& with_context(std::string_view ctx) & {
 *          set_or_throw(m_context, std::string(ctx));
 *          return *this;
 *       }
 *
 *       KDF_Builder with_context(std::string_view ctx) && {
 *          return std::move(with_context(ctx));
 *       }
 *
 *       KDF_Builder& with_label(std::string_view label) & {
 *          set_or_throw(m_context, std::string(label));
 *          return *this;
 *       }
 *
 *       KDF_Builder with_label(std::string_view label) && {
 *          return std::move(with_label(label));
 *       }
 *
 *       KDF_Builder& with_hash(std::string_view hash) & {
 *          set_or_throw(m_hash, Botan::HashFunction::create_or_throw(hash));
 *          return *this;
 *       }
 *
 *       KDF_Builder with_hash(std::string_view hash) && {
 *          return std::move(with_hash(hash));
 *       }
 *
 *       KDF_Builder& with_hash(std::unique_ptr<HashFunction> hash) & {
 *          set_or_throw(m_hash, std::move(hash));
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
 *          KDF kdf(*this);
 *          validate_option_consumption();
 *          return kdf;
 *       }
 *
 *       /// Gets the context value or std::nullopt if it wasn't set
 *       std::optional<std::string> context() { return take(context); }
 *
 *       /// Gets the label value or a default if it wasn't set
 *       std::string label() { return take(label).value_or("default"); }
 *
 *       /// Gets the hash function or throws if it wasn't set
 *       std::unique_ptr<HashFunction> hash() { return require(hash); }
 * };
 */
template <typename DerivedT>
class Builder {
   public:
      [[nodiscard]] std::string to_string() const {
         std::ostringstream oss;
         foreach_option([&]<detail::BuilderOption OptionT>(const OptionT& option) {
            oss << OptionT::name << ": " << option.to_string() << '\n';
         });
         return oss.str();
      }

   protected:
      void set_product_name(std::string_view name) { m_product_name = std::string(name); }

      [[nodiscard]] static auto take(detail::BuilderOption auto& o) noexcept {
         return std::exchange(o.value, std::nullopt);
      }

      template <detail::BuilderOption OptionT>
      [[nodiscard]] auto require(OptionT& o) {
         if(!o.value.has_value()) {
            throw Invalid_Argument("'" + m_product_name + "' requires the '" + std::string(OptionT::name) + "' option");
         }
         return take(o).value();
      }

      template <detail::BuilderOption OptionT, std::convertible_to<typename OptionT::value_type> ValueT>
      void set_or_throw(OptionT& option, ValueT&& value) {
         if(option.value.has_value()) {
            throw Invalid_State("'" + m_product_name + "' already set the '" + std::string(OptionT::name) + "' option");
         }
         option.value.emplace(std::forward<ValueT>(value));
      }

      template <typename FnT>
      void foreach_option(FnT&& fn) const {
         // TODO: C++23: using deducing-this we can remove the CRTP and simply
         //              deduce the DerivedT from the explicit object parameter.
         std::apply([&]<detail::BuilderOption... OptionTs>(const OptionTs&... options) { (fn(options), ...); },
                    static_cast<const DerivedT&>(*this).all_options());
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

   private:
      std::string m_product_name = "Unknown";
};

}  // namespace Botan

#endif
