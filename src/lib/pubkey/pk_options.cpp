/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pk_options.h>

#include <botan/hash.h>
#include <botan/hex.h>
#include <botan/mem_ops.h>
#include <botan/internal/fmt.h>
#include <sstream>

namespace Botan {

PK_Signature_Options::~PK_Signature_Options() = default;

PK_Signature_Options PK_Signature_Options::with_hash(std::string_view hash) && {
   BOTAN_STATE_CHECK_MSG(!using_hash(), "PK_Signature_Options::with_hash cannot specify hash twice");
   if(!hash.empty()) {
      this->m_hash_fn = hash;
   }
   return std::move(*this);
}

PK_Signature_Options PK_Signature_Options::with_padding(std::string_view padding) && {
   BOTAN_STATE_CHECK_MSG(!using_padding(), "PK_Signature_Options::with_padding cannot specify padding twice");
   if(!padding.empty()) {
      this->m_padding = padding;
   }
   return std::move(*this);
}

PK_Signature_Options PK_Signature_Options::with_prehash(std::optional<std::string> prehash_fn) && {
   BOTAN_STATE_CHECK_MSG(!using_prehash(), "PK_Signature_Options::with_prehash cannot specify prehash twice");
   this->m_using_prehash = true;
   this->m_prehash = std::move(prehash_fn);
   return std::move(*this);
}

PK_Signature_Options PK_Signature_Options::with_provider(std::string_view provider) && {
   if(!provider.empty()) {
      BOTAN_STATE_CHECK_MSG(!using_provider(), "PK_Signature_Options::with_provider cannot specify provider twice");
      this->m_provider = provider;
   }
   return std::move(*this);
}

PK_Signature_Options PK_Signature_Options::with_context(std::span<const uint8_t> context) && {
   BOTAN_STATE_CHECK_MSG(!using_context(), "PK_Signature_Options::with_context cannot specify context twice");
   this->m_context = std::vector<uint8_t>(context.begin(), context.end());
   return std::move(*this);
}

PK_Signature_Options PK_Signature_Options::with_context(std::string_view context) && {
   BOTAN_STATE_CHECK_MSG(!using_context(), "PK_Signature_Options::with_context cannot specify context twice");
   const uint8_t* ptr = cast_char_ptr_to_uint8(context.data());
   this->m_context = std::vector<uint8_t>(ptr, ptr + context.size());
   return std::move(*this);
}

PK_Signature_Options PK_Signature_Options::with_salt_size(size_t salt_size) && {
   BOTAN_STATE_CHECK_MSG(!using_salt_size(), "PK_Signature_Options::with_salt_size cannot specify salt size twice");
   this->m_salt_size = salt_size;
   return std::move(*this);
}

PK_Signature_Options PK_Signature_Options::with_deterministic_signature() && {
   this->m_deterministic_sig = true;
   return std::move(*this);
}

PK_Signature_Options PK_Signature_Options::with_der_encoded_signature(bool der) && {
   this->m_use_der = der;
   return std::move(*this);
}

PK_Signature_Options PK_Signature_Options::with_explicit_trailer_field() && {
   this->m_explicit_trailer_field = true;
   return std::move(*this);
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
