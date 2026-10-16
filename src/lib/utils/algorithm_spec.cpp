/*
* Algorithm Specification Parsing and Matching
* (C) 2008,2015,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/algorithm_spec.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/internal/fmt.h>
#include <botan/internal/parsing.h>

namespace Botan {

namespace {

constexpr size_t MaxNestingDepth = 16;

bool is_spec_separator(char c, bool slash_separates) {
   return c == '(' || c == ')' || c == ',' || (slash_separates && c == '/');
}

}  // namespace

//static
AlgorithmSpec AlgorithmSpec::parse_name(std::string_view text, size_t& pos, size_t depth, bool mode_syntax) {
   if(depth > MaxNestingDepth) {
      throw Invalid_Algorithm_Name(text);
   }

   // The '/' separator is only significant at the top level of a cipher mode
   const bool slash_separates = mode_syntax && (depth == 0);
   const size_t start = pos;

   while(pos < text.size() && !is_spec_separator(text[pos], slash_separates)) {
      ++pos;
   }

   AlgorithmSpec node;
   node.m_head = std::string(text.substr(start, pos - start));

   if(node.m_head.empty()) {
      throw Invalid_Algorithm_Name(text);
   }

   if(pos < text.size() && text[pos] == '(') {
      do {       // NOLINT(*-avoid-do-while)
         ++pos;  // skip the '(' or ','
         node.m_args.push_back(parse_name(text, pos, depth + 1, mode_syntax));
      } while(pos < text.size() && text[pos] == ',');

      if(pos >= text.size() || text[pos] != ')') {
         throw Invalid_Algorithm_Name(text);
      }
      ++pos;
   }

   node.m_text = std::string(text.substr(start, pos - start));
   return node;
}

AlgorithmSpec::AlgorithmSpec(std::string_view spec, Syntax syntax) {
   if(spec.empty()) {
      throw Invalid_Algorithm_Name(spec);
   }

   const bool mode_syntax = (syntax == Syntax::CipherMode);

   // Fast path for a bare name such as "SHA-256", which is the common case
   if(spec.find_first_of(mode_syntax ? "(),/" : "(),") == std::string_view::npos) {
      m_text = std::string(spec);
      m_head = std::string(spec);
      return;
   }

   size_t pos = 0;
   std::vector<AlgorithmSpec> parts;
   parts.push_back(parse_name(spec, pos, 0, mode_syntax));

   while(mode_syntax && pos < spec.size() && spec[pos] == '/') {
      ++pos;
      parts.push_back(parse_name(spec, pos, 0, mode_syntax));
   }

   if(pos != spec.size()) {
      throw Invalid_Algorithm_Name(spec);
   }

   if(parts.size() == 1) {
      m_head = std::move(parts[0].m_head);
      m_args = std::move(parts[0].m_args);
   } else {
      // Cipher/Mode(args)/Pad becomes Mode(Cipher,args,Pad)
      AlgorithmSpec& mode = parts[1];
      m_head = std::move(mode.m_head);
      m_args.push_back(std::move(parts[0]));
      for(auto& mode_arg : mode.m_args) {
         m_args.push_back(std::move(mode_arg));
      }
      for(size_t i = 2; i < parts.size(); ++i) {
         m_args.push_back(std::move(parts[i]));
      }
   }

   m_text = std::string(spec);
}

const AlgorithmSpec& AlgorithmSpec::arg(size_t i) const {
   if(i >= m_args.size()) {
      throw Invalid_Argument(fmt("AlgorithmSpec::arg {} out of range for '{}'", i, m_text));
   }
   return m_args[i];
}

std::string AlgorithmSpec::text_with_head(std::string_view head) const {
   std::string text(head);
   if(!m_args.empty()) {
      text += '(';
      for(size_t i = 0; i != m_args.size(); ++i) {
         if(i > 0) {
            text += ',';
         }
         text += m_args[i].m_text;
      }
      text += ')';
   }
   return text;
}

std::optional<AlgorithmMatch> AlgorithmSpec::match(const AlgorithmPattern& pattern) const& {
   // Factories try many patterns in turn, so reject on the head before
   // setting up the (fairly large) match object
   if(!pattern.any_head()) {
      bool head_matches = false;
      for(const auto alt : pattern.head_alternatives()) {
         if(alt == m_head) {
            head_matches = true;
            break;
         }
      }
      if(!head_matches) {
         return std::nullopt;
      }
   }

   AlgorithmMatch m(pattern, *this);

   size_t idx = 0;
   if(!match_args(pattern.elements(), idx, 0, m)) {
      return std::nullopt;
   }

   return m;
}

bool AlgorithmSpec::match_args(std::span<const AlgorithmPattern::Element> elems,
                               size_t& idx,
                               uint8_t depth,
                               AlgorithmMatch& m) const {
   using Type = AlgorithmPattern::Type;

   size_t arg_idx = 0;

   while(idx < elems.size() && elems[idx].depth == depth) {
      const auto& e = elems[idx];
      ++idx;

      if(arg_idx >= m_args.size()) {
         // No argument was provided for this element
         if(!e.optional) {
            return false;
         }

         if(e.placeholder && e.has_default) {
            auto& b = m.declared(e.text);
            b.bound = true;
            b.text = e.default_value;
            if(e.type == Type::Int) {
               // The pattern parser already checked this is a canonical decimal
               const auto v = parse_sz(e.default_value, true);
               BOTAN_ASSERT_NOMSG(v.has_value());
               b.integer = *v;
            }
         }

         continue;
      }

      const AlgorithmSpec& arg = m_args[arg_idx];

      if(e.variadic) {
         auto& b = m.declared(e.text);
         b.bound = true;
         b.rest = std::span(m_args).subspan(arg_idx);
         arg_idx = m_args.size();
         continue;
      }

      if(e.placeholder) {
         auto& b = m.declared(e.text);

         if(e.type == Type::Int) {
            if(!arg.m_args.empty()) {
               return false;
            }
            const auto v = parse_sz(arg.m_text, true);
            if(!v) {
               return false;
            }
            b.integer = *v;
         }

         b.bound = true;
         b.text = arg.m_text;
         b.node = &arg;
      } else if(e.optional) {
         // An optional literal which is not present is skipped without consuming the argument
         if(arg.m_head != e.text || !arg.m_args.empty()) {
            continue;
         }
      } else {
         if(arg.m_head != e.text) {
            return false;
         }

         if(idx < elems.size() && elems[idx].depth == depth + 1) {
            if(!arg.match_args(elems, idx, depth + 1, m)) {
               return false;
            }
         } else if(!arg.m_args.empty()) {
            return false;
         }
      }

      ++arg_idx;
   }

   return arg_idx == m_args.size();
}

AlgorithmMatch::AlgorithmMatch(const AlgorithmPattern& pattern, const AlgorithmSpec& spec) :
      m_pattern(pattern.to_string()), m_head(spec.head()) {
   for(const auto& e : pattern.elements()) {
      if(e.placeholder) {
         Binding b;
         b.var = e.text;
         b.type = e.type;
         b.variadic = e.variadic;
         m_bindings[m_binding_count++] = b;
      }
   }
}

AlgorithmMatch::Binding& AlgorithmMatch::declared(std::string_view var) {
   for(size_t i = 0; i != m_binding_count; ++i) {
      if(m_bindings[i].var == var) {
         return m_bindings[i];
      }
   }
   throw Internal_Error(fmt("AlgorithmMatch: no variable '{}' in pattern '{}'", var, m_pattern));
}

const AlgorithmMatch::Binding& AlgorithmMatch::bound(std::string_view var, const char* accessor) const {
   for(size_t i = 0; i != m_binding_count; ++i) {
      if(m_bindings[i].var == var) {
         if(!m_bindings[i].bound) {
            throw Internal_Error(
               fmt("AlgorithmMatch::{}: variable '{}' in pattern '{}' was not bound; check has() first",
                   accessor,
                   var,
                   m_pattern));
         }
         return m_bindings[i];
      }
   }
   throw Internal_Error(fmt("AlgorithmMatch::{}: no variable '{}' in pattern '{}'", accessor, var, m_pattern));
}

bool AlgorithmMatch::has(std::string_view var) const {
   for(size_t i = 0; i != m_binding_count; ++i) {
      if(m_bindings[i].var == var) {
         return m_bindings[i].bound;
      }
   }
   throw Internal_Error(fmt("AlgorithmMatch::has: no variable '{}' in pattern '{}'", var, m_pattern));
}

std::string_view AlgorithmMatch::str(std::string_view var) const {
   const auto& b = bound(var, "str");
   if(b.variadic) {
      throw Internal_Error(fmt("AlgorithmMatch::str: variable '{}' in pattern '{}' is variadic", var, m_pattern));
   }
   return b.text;
}

size_t AlgorithmMatch::integer(std::string_view var) const {
   const auto& b = bound(var, "integer");
   if(b.type != AlgorithmPattern::Type::Int) {
      throw Internal_Error(fmt("AlgorithmMatch::integer: variable '{}' in pattern '{}' is not an int", var, m_pattern));
   }
   return b.integer;
}

const AlgorithmSpec& AlgorithmMatch::name(std::string_view var) const {
   const auto& b = bound(var, "name");
   if(b.type != AlgorithmPattern::Type::Name || b.variadic || b.node == nullptr) {
      throw Internal_Error(fmt("AlgorithmMatch::name: variable '{}' in pattern '{}' is not a name", var, m_pattern));
   }
   return *b.node;
}

std::span<const AlgorithmSpec> AlgorithmMatch::rest(std::string_view var) const {
   const auto& b = bound(var, "rest");
   if(!b.variadic) {
      throw Internal_Error(fmt("AlgorithmMatch::rest: variable '{}' in pattern '{}' is not variadic", var, m_pattern));
   }
   return b.rest;
}

}  // namespace Botan
