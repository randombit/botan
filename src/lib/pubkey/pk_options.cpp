/*
* (C) 2024,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pk_options.h>

#include <botan/assert.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include <botan/internal/fmt.h>
#include <botan/internal/mem_utils.h>
#include <sstream>

namespace Botan {

PK_Signature_Options::~PK_Signature_Options() = default;

PK_Signature_Options PK_Signature_Options::with_hash(std::string_view hash) {
   BOTAN_STATE_CHECK_MSG(!using_hash(), "PK_Signature_Options::with_hash cannot specify hash twice");
   auto next = (*this);
   if(!hash.empty()) {
      next.m_hash_fn = hash;
   }
   return next;
}

PK_Signature_Options PK_Signature_Options::with_padding(std::string_view padding) {
   BOTAN_STATE_CHECK_MSG(!using_padding(), "PK_Signature_Options::with_padding cannot specify padding twice");
   auto next = (*this);
   if(!padding.empty()) {
      next.m_padding = padding;
   }
   return next;
}

PK_Signature_Options PK_Signature_Options::with_prehash(std::optional<std::string> prehash_fn) {
   BOTAN_STATE_CHECK_MSG(!using_prehash(), "PK_Signature_Options::with_prehash cannot specify prehash twice");
   auto next = (*this);
   next.m_using_prehash = true;
   next.m_prehash = std::move(prehash_fn);
   return next;
}

PK_Signature_Options PK_Signature_Options::with_provider(std::string_view provider) {
   BOTAN_STATE_CHECK_MSG(provider.empty() || !using_provider(),
                         "PK_Signature_Options::with_provider cannot specify provider twice");
   auto next = (*this);
   if(!provider.empty()) {
      next.m_provider = provider;
   }
   return next;
}

PK_Signature_Options PK_Signature_Options::with_context(std::span<const uint8_t> context) {
   BOTAN_STATE_CHECK_MSG(!using_context(), "PK_Signature_Options::with_context cannot specify context twice");
   auto next = (*this);
   next.m_context = std::vector<uint8_t>(context.begin(), context.end());
   return next;
}

PK_Signature_Options PK_Signature_Options::with_context(std::string_view context) {
   BOTAN_STATE_CHECK_MSG(!using_context(), "PK_Signature_Options::with_context cannot specify context twice");
   auto next = (*this);
   auto contextb = as_span_of_bytes(context);
   next.m_context = std::vector<uint8_t>(contextb.begin(), contextb.end());
   return next;
}

PK_Signature_Options PK_Signature_Options::with_salt_size(size_t salt_size) {
   BOTAN_STATE_CHECK_MSG(!using_salt_size(), "PK_Signature_Options::with_salt_size cannot specify salt size twice");
   auto next = (*this);
   next.m_salt_size = salt_size;
   return next;
}

PK_Signature_Options PK_Signature_Options::with_deterministic_signature() {
   auto next = (*this);
   next.m_deterministic_sig = true;
   return next;
}

PK_Signature_Options PK_Signature_Options::with_der_encoded_signature(bool der) {
   auto next = (*this);
   next.m_use_der = der;
   return next;
}

PK_Signature_Options PK_Signature_Options::with_explicit_trailer_field() {
   auto next = (*this);
   next.m_explicit_trailer_field = true;
   return next;
}

bool PK_Signature_Options::using_provider() const {
   if(auto prov = provider()) {
      return !prov->empty() && *prov != "base";
   }
   return false;
}

std::string PK_Signature_Options::hash_function_name() const {
   if(m_hash_fn.has_value()) {
      return m_hash_fn.value();
   }

   throw Invalid_State("This signature scheme requires specifying a hash function");
}

std::string PK_Signature_Options::to_string() const {
   std::ostringstream out;

   auto print_str = [&](std::string_view name, std::optional<std::string> val) {
      if(val.has_value()) {
         out << name << "='" << val.value() << "' ";
      }
   };

   print_str("Hash", this->hash_function());
   print_str("Padding", this->padding());
   print_str("Prehash", this->prehash_fn());
   print_str("Provider", this->provider());

   if(auto context = this->context()) {
      out << "Context=" << hex_encode(*context) << " ";
   }

   if(auto salt = this->salt_size()) {
      out << "SaltLen=" << *salt << " ";
   }
   if(this->using_der_encoded_signature()) {
      out << "DerSignature ";
   }
   if(this->using_deterministic_signature()) {
      out << "Deterministic ";
   }

   return out.str();
}

}  // namespace Botan
