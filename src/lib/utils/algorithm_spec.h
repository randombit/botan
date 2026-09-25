/*
* Algorithm Specification Parsing and Matching
* (C) 2008,2015,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ALGORITHM_SPEC_H_
#define BOTAN_ALGORITHM_SPEC_H_

#include <botan/assert.h>
#include <botan/types.h>
#include <array>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Botan {

class AlgorithmSpec;
class AlgorithmMatch;

/**
* A compile-time validated pattern describing the accepted form of an algorithm
* specification. See AlgorithmSpec::match for how patterns are used.
*
* Pattern grammar:
*
*   pattern     := head [ '(' element (',' element)* ')' ]
*   head        := token ('|' token)*                    alternatives (aliases)
*                | '*'                                   any head
*   element     := placeholder [ '...' ]                 '...' = one or more, must be last
*                | literal                              a token which must appear
*                | '[' literal ']'                      an optional literal, skipped if absent
*                | token '(' element (',' element)* ')' a literal with nested elements
*   placeholder := '{' ident [':' type] ['=' default | '?'] '}'
*   type        := name | int | str                     default is name
*
* A placeholder with a default ('=') or marked '?' is optional. Once an optional
* element appears, every following element must also be optional. Defaults are
* only permitted for int and str placeholders. An int must be a canonical
* decimal integer with no arguments; a str binds the text of the argument
* verbatim, including any nested arguments; a name binds the argument as a
* specification for passing on to another factory.
*
* A '*' head matches any name, with AlgorithmMatch::head reporting which one.
* This is for provider wrappers which immediately look the head up in a table
* of supported algorithms; a factory pattern should always name its heads.
*
* Patterns are only constructible from string literals, so a pattern and any
* match made from it may reference the pattern text indefinitely.
*/
class BOTAN_TEST_API AlgorithmPattern final {
   public:
      static constexpr size_t MaxElements = 4;
      // TODO(Botan4) reduce this when deprecated aliases are dropped
      static constexpr size_t MaxHeadAlternatives = 4;

      // This is actually only "thrown" at compile time which is why it
      // does not derive from a standard Botan exception base
      class InvalidAlgorithmPattern final : public std::exception {
         public:
            explicit InvalidAlgorithmPattern(const char* msg) : m_msg(msg) {}

            const char* what() const noexcept final { return m_msg; }

         private:
            const char* m_msg;
      };

      enum class Type : uint8_t {
         Name,
         Int,
         Str,
      };

      struct Element {
            std::string_view text;  // literal token, or placeholder variable name
            std::string_view default_value;
            Type type = Type::Name;
            uint8_t depth = 0;
            bool placeholder = false;
            bool optional = false;
            bool has_default = false;
            bool variadic = false;
      };

      /**
      * Construct a pattern from a string literal. The pattern is parsed and
      * validated at compile time; a malformed pattern is a compile error.
      */
      template <size_t N>
      consteval AlgorithmPattern(const char (&pattern)[N]) :  // NOLINT(*-explicit-conversions)
            AlgorithmPattern(std::string_view(pattern, N - 1)) {}

      std::string_view to_string() const { return m_text; }

      /**
      * @return true if the pattern accepts any head
      */
      bool any_head() const { return m_head_count == 0; }

      std::span<const std::string_view> head_alternatives() const { return std::span(m_heads).first(m_head_count); }

      std::span<const Element> elements() const { return std::span(m_elements).first(m_element_count); }

   private:
      explicit constexpr AlgorithmPattern(std::string_view pattern);

      constexpr void parse_pattern(std::string_view p);
      constexpr void parse_elements(std::string_view p, size_t& pos, uint8_t depth);
      constexpr void parse_placeholder(std::string_view p, size_t& pos, Element& e) const;

      static constexpr bool is_token_char(char c) {
         return c != '(' && c != ')' && c != '{' && c != '}' && c != '[' && c != ']' && c != ',' && c != '|' &&
                c != '*';
      }

      template <typename Pred>
      static constexpr std::string_view read_while(std::string_view p, size_t& pos, Pred pred) {
         const size_t start = pos;
         while(pos < p.size() && pred(p[pos])) {
            ++pos;
         }
         return p.substr(start, pos - start);
      }

      std::string_view m_text;
      std::array<std::string_view, MaxHeadAlternatives> m_heads{};
      // A '*' head is encoded as an empty list (boolean hits a Clang 14 codegen bug)
      size_t m_head_count = 0;
      std::array<Element, MaxElements> m_elements{};
      size_t m_element_count = 0;
};

/**
* A parsed algorithm specification such as "HMAC(SHA-256)" or "AES-128/GCM(12)"
*
* Specifications have the form Head(arg,arg,...) where each argument is itself
* a specification. With Syntax::CipherMode the form "Cipher/Mode(args)/Pad" is
* also accepted at the top level and canonicalized to "Mode(Cipher,args,Pad)";
* otherwise a slash is an ordinary character.
*
* Factories should match against an AlgorithmPattern, which expresses the
* entire accepted form including defaults, rather than inspecting arguments
* positionally.
*/
class BOTAN_TEST_API AlgorithmSpec final {
   public:
      enum class Syntax : uint8_t {
         Standard,
         CipherMode,
      };

      /**
      * Parse a specification
      * @throws Invalid_Algorithm_Name if the string is malformed
      */
      explicit AlgorithmSpec(std::string_view spec, Syntax syntax = Syntax::Standard);

      /**
      * @return the original text of the specification
      */
      std::string_view to_string() const { return m_text; }

      /**
      * @return the outermost algorithm name, eg "GCM" for "AES-128/GCM"
      */
      std::string_view head() const { return m_head; }

      size_t arg_count() const { return m_args.size(); }

      std::span<const AlgorithmSpec> args() const { return m_args; }

      /**
      * @return the ith argument
      * @throws Invalid_Argument if i is out of range
      */
      const AlgorithmSpec& arg(size_t i) const;

      /**
      * @return the specification written as Head(arg,arg,...), which differs
      * from to_string only for the cipher mode syntax
      */
      std::string canonical_form() const { return text_with_head(m_head); }

      /**
      * @return a copy of this specification with the head replaced, for
      * folding deprecated aliases before matching
      */
      AlgorithmSpec with_head(std::string_view head) const { return AlgorithmSpec(text_with_head(head)); }

      /**
      * Match this specification against a pattern
      *
      * @return the bound variables, or nullopt if the pattern does not match.
      * The result references this object and must not outlive it.
      */
      std::optional<AlgorithmMatch> match(const AlgorithmPattern& pattern) const&;

      // The match refers into this spec, so it cannot outlive a temporary
      std::optional<AlgorithmMatch> match(const AlgorithmPattern& pattern) const&& = delete;

      /**
      * @return true if this specification matches the pattern
      */
      bool matches(const AlgorithmPattern& pattern) const;

   private:
      AlgorithmSpec() = default;

      static AlgorithmSpec parse_name(std::string_view text, size_t& pos, size_t depth, bool mode_syntax);

      std::string text_with_head(std::string_view head) const;

      bool match_args(std::span<const AlgorithmPattern::Element> elems,
                      size_t& idx,
                      uint8_t depth,
                      AlgorithmMatch& m) const;

      std::string m_text;
      std::string m_head;
      std::vector<AlgorithmSpec> m_args;
};

/**
* The variables bound by a successful AlgorithmSpec::match
*
* Requesting a variable which the pattern does not declare, or with an accessor
* that does not fit its type, is a programmer error and throws Internal_Error.
*/
class BOTAN_TEST_API AlgorithmMatch final {
   public:
      /**
      * @return the head of the matched specification, which is useful when the
      * pattern lists several alternatives
      */
      std::string_view head() const { return m_head; }

      /**
      * @return true if the variable was bound, either from the input or a default
      */
      bool has(std::string_view var) const;

      /**
      * @return the text bound to a variable of any type
      */
      std::string_view str(std::string_view var) const;

      /**
      * @return the value bound to an int variable
      */
      size_t integer(std::string_view var) const;

      /**
      * @return the specification bound to a name variable
      */
      const AlgorithmSpec& name(std::string_view var) const;

      /**
      * @return the specifications bound to a variadic variable
      */
      std::span<const AlgorithmSpec> rest(std::string_view var) const;

   private:
      friend class AlgorithmSpec;

      struct Binding {
            std::string_view var;
            AlgorithmPattern::Type type = AlgorithmPattern::Type::Name;
            bool variadic = false;
            bool bound = false;
            std::string_view text;
            size_t integer = 0;
            const AlgorithmSpec* node = nullptr;
            std::span<const AlgorithmSpec> rest;
      };

      AlgorithmMatch(const AlgorithmPattern& pattern, const AlgorithmSpec& spec);

      Binding& declared(std::string_view var);
      const Binding& bound(std::string_view var, const char* accessor) const;

      std::string_view m_pattern;
      std::string_view m_head;
      std::array<Binding, AlgorithmPattern::MaxElements> m_bindings{};
      size_t m_binding_count = 0;
};

inline bool AlgorithmSpec::matches(const AlgorithmPattern& pattern) const {
   return match(pattern).has_value();
}

// Implementation of the compile time pattern parser follows

constexpr AlgorithmPattern::AlgorithmPattern(std::string_view pattern) : m_text(pattern) {
   parse_pattern(pattern);
}

constexpr void AlgorithmPattern::parse_placeholder(std::string_view p, size_t& pos, Element& e) const {
   auto is_ident_char = [](char c) {
      return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
   };

   auto is_canonical_decimal = [](std::string_view s) {
      // Upper bound is arbitrary but sufficient
      if(s.empty() || s.size() > 10) {
         return false;
      }
      // Don't accept leading 0s except for literal "0"
      if(s.size() > 1 && s[0] == '0') {
         return false;
      }
      for(const char c : s) {
         if(c < '0' || c > '9') {
            return false;
         }
      }
      return true;
   };

   BOTAN_ASSERT_NOMSG(pos < p.size() && p[pos] == '{');
   ++pos;

   e.placeholder = true;
   e.text = read_while(p, pos, is_ident_char);
   if(e.text.empty()) {
      throw InvalidAlgorithmPattern("AlgorithmPattern: placeholder without a name");
   }

   if(pos < p.size() && p[pos] == ':') {
      ++pos;
      const auto type = read_while(p, pos, is_ident_char);
      if(type == "name") {
         e.type = Type::Name;
      } else if(type == "int") {
         e.type = Type::Int;
      } else if(type == "str") {
         e.type = Type::Str;
      } else {
         throw InvalidAlgorithmPattern("AlgorithmPattern: unknown placeholder type");
      }
   }

   if(pos < p.size() && p[pos] == '=') {
      ++pos;
      const size_t start = pos;
      while(pos < p.size() && p[pos] != '}') {
         ++pos;
      }
      e.default_value = p.substr(start, pos - start);
      e.optional = true;
      e.has_default = true;

      if(e.type == Type::Name) {
         throw InvalidAlgorithmPattern("AlgorithmPattern: only int and str placeholders can have a default");
      }
      if(e.type == Type::Int && !is_canonical_decimal(e.default_value)) {
         throw InvalidAlgorithmPattern("AlgorithmPattern: int default is not a canonical decimal integer");
      }
   } else if(pos < p.size() && p[pos] == '?') {
      ++pos;
      e.optional = true;
   }

   if(pos >= p.size() || p[pos] != '}') {
      throw InvalidAlgorithmPattern("AlgorithmPattern: expected '}'");
   }
   ++pos;
}

constexpr void AlgorithmPattern::parse_elements(std::string_view p, size_t& pos, uint8_t depth) {
   // pos is just past the '('
   bool seen_optional = false;
   bool seen_variadic = false;

   for(;;) {
      if(pos >= p.size()) {
         throw InvalidAlgorithmPattern("AlgorithmPattern: unterminated element list");
      }
      if(seen_variadic) {
         throw InvalidAlgorithmPattern("AlgorithmPattern: variadic placeholder must be the last element");
      }
      if(m_element_count == MaxElements) {
         throw InvalidAlgorithmPattern("AlgorithmPattern: too many elements");
      }

      Element e;
      e.depth = depth;
      bool pushed = false;

      if(p[pos] == '{') {
         parse_placeholder(p, pos, e);
         if(p.substr(pos, 3) == "...") {
            pos += 3;
            if(e.optional) {
               throw InvalidAlgorithmPattern("AlgorithmPattern: variadic placeholder cannot be optional");
            }
            if(e.type != Type::Name) {
               throw InvalidAlgorithmPattern("AlgorithmPattern: variadic placeholder must have type name");
            }
            e.variadic = true;
            seen_variadic = true;
         }
      } else if(p[pos] == '[') {
         ++pos;
         e.text = read_while(p, pos, is_token_char);
         if(e.text.empty()) {
            throw InvalidAlgorithmPattern("AlgorithmPattern: empty optional literal");
         }
         if(pos >= p.size() || p[pos] != ']') {
            throw InvalidAlgorithmPattern("AlgorithmPattern: expected ']'");
         }
         ++pos;
         e.optional = true;
      } else {
         e.text = read_while(p, pos, is_token_char);
         if(e.text.empty()) {
            throw InvalidAlgorithmPattern("AlgorithmPattern: empty element");
         }
         if(pos < p.size() && p[pos] == '(') {
            if(seen_optional) {
               throw InvalidAlgorithmPattern("AlgorithmPattern: required element after optional element");
            }
            if(static_cast<size_t>(depth) + 1 >= MaxElements) {
               throw InvalidAlgorithmPattern("AlgorithmPattern: nesting too deep");
            }
            m_elements[m_element_count++] = e;
            pushed = true;
            ++pos;
            parse_elements(p, pos, static_cast<uint8_t>(depth + 1));
         }
      }

      if(e.optional) {
         seen_optional = true;
      } else if(seen_optional) {
         throw InvalidAlgorithmPattern("AlgorithmPattern: required element after optional element");
      }

      if(!pushed) {
         m_elements[m_element_count++] = e;
      }

      if(pos >= p.size()) {
         throw InvalidAlgorithmPattern("AlgorithmPattern: unterminated element list");
      }
      if(p[pos] == ',') {
         ++pos;
         continue;
      }
      if(p[pos] == ')') {
         ++pos;
         return;  // done
      }
      throw InvalidAlgorithmPattern("AlgorithmPattern: unexpected character in element list");
   }
}

constexpr void AlgorithmPattern::parse_pattern(std::string_view p) {
   size_t pos = 0;

   if(p.empty()) {
      throw InvalidAlgorithmPattern("AlgorithmPattern: empty pattern");
   }

   if(p[pos] == '*') {
      ++pos;
      if(pos < p.size() && p[pos] == '|') {
         throw InvalidAlgorithmPattern("AlgorithmPattern: wildcard head cannot have alternatives");
      }
   } else {
      for(;;) {
         if(m_head_count == MaxHeadAlternatives) {
            throw InvalidAlgorithmPattern("AlgorithmPattern: too many head alternatives");
         }
         const auto tok = read_while(p, pos, is_token_char);
         if(tok.empty()) {
            throw InvalidAlgorithmPattern("AlgorithmPattern: empty head");
         }
         m_heads[m_head_count++] = tok;
         if(pos < p.size() && p[pos] == '|') {
            ++pos;
            continue;
         }
         break;
      }
   }

   if(pos < p.size()) {
      if(p[pos] != '(') {
         throw InvalidAlgorithmPattern("AlgorithmPattern: unexpected character after head");
      }
      ++pos;
      parse_elements(p, pos, 0);
      if(pos != p.size()) {
         throw InvalidAlgorithmPattern("AlgorithmPattern: trailing characters");
      }
   }

   // Variable names must be unique
   for(size_t i = 0; i != m_element_count; ++i) {
      if(!m_elements[i].placeholder) {
         continue;
      }
      for(size_t j = 0; j != i; ++j) {
         if(m_elements[j].placeholder && m_elements[j].text == m_elements[i].text) {
            throw InvalidAlgorithmPattern("AlgorithmPattern: duplicate variable name");
         }
      }
   }

   // accept
}

}  // namespace Botan

#endif
