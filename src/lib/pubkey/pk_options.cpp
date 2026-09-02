/*
* (C) 2024,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pk_options.h>

#include <botan/assert.h>
#include <botan/hex.h>
#include <botan/internal/fmt.h>
#include <botan/internal/mem_utils.h>
#include <initializer_list>
#include <sstream>
#include <utility>

namespace Botan {

PK_Signature_Options::~PK_Signature_Options() = default;

PK_Signature_Options PK_Signature_Options::with_hash(std::string_view hash) {
   BOTAN_STATE_CHECK_MSG(!m_hash_fn.has_value(), "PK_Signature_Options::with_hash cannot specify hash twice");
   auto next = (*this);
   if(!hash.empty()) {
      next.m_hash_fn = hash;
   }
   return next;
}

PK_Signature_Options PK_Signature_Options::with_padding(std::string_view padding) {
   BOTAN_STATE_CHECK_MSG(!m_padding.has_value(), "PK_Signature_Options::with_padding cannot specify padding twice");
   auto next = (*this);
   if(!padding.empty()) {
      next.m_padding = padding;
   }
   return next;
}

PK_Signature_Options PK_Signature_Options::with_prehash(std::optional<std::string> prehash_function) {
   BOTAN_STATE_CHECK_MSG(!m_using_prehash, "PK_Signature_Options::with_prehash cannot specify prehash twice");
   BOTAN_STATE_CHECK_MSG(!m_using_external_prehash,
                         "PK_Signature_Options::with_prehash cannot be combined with an externally computed prehash");
   auto next = (*this);

   // Calling this with a std::nullopt enables prehashing with an algorithm-
   // specific hash function that is not user-defined. Hence the bool flag.
   next.m_using_prehash = true;
   next.m_prehash = std::move(prehash_function);
   return next;
}

PK_Signature_Options PK_Signature_Options::with_externally_computed_prehash(std::optional<std::string> hash) {
   BOTAN_STATE_CHECK_MSG(
      !m_using_external_prehash,
      "PK_Signature_Options::with_externally_computed_prehash cannot specify external prehash twice");
   BOTAN_STATE_CHECK_MSG(!m_using_prehash,
                         "PK_Signature_Options::with_externally_computed_prehash cannot be combined with a prehash");
   auto next = (*this);

   // As with with_prehash, a nullopt hash is meaningful (the input is an
   // unidentified digest) so a flag tracks that the option was requested
   next.m_using_external_prehash = true;
   next.m_external_prehash = std::move(hash);
   return next;
}

PK_Signature_Options PK_Signature_Options::with_provider(std::string_view provider) {
   BOTAN_STATE_CHECK_MSG(provider.empty() || !m_provider.has_value(),
                         "PK_Signature_Options::with_provider cannot specify provider twice");
   auto next = (*this);
   if(!provider.empty()) {
      next.m_provider = provider;
   }
   return next;
}

PK_Signature_Options PK_Signature_Options::with_context(std::span<const uint8_t> context) {
   BOTAN_STATE_CHECK_MSG(!m_context.has_value(), "PK_Signature_Options::with_context cannot specify context twice");
   auto next = (*this);
   next.m_context = std::vector<uint8_t>(context.begin(), context.end());
   return next;
}

PK_Signature_Options PK_Signature_Options::with_context(std::string_view context) {
   BOTAN_STATE_CHECK_MSG(!m_context.has_value(), "PK_Signature_Options::with_context cannot specify context twice");
   auto next = (*this);
   auto contextb = as_span_of_bytes(context);
   next.m_context = std::vector<uint8_t>(contextb.begin(), contextb.end());
   return next;
}

PK_Signature_Options PK_Signature_Options::with_salt_size(size_t salt_size) {
   BOTAN_STATE_CHECK_MSG(!m_salt_size.has_value(),
                         "PK_Signature_Options::with_salt_size cannot specify salt size twice");
   BOTAN_ARG_CHECK(salt_size <= 1024, "Unreasonable salt size");
   auto next = (*this);
   next.m_salt_size = salt_size;
   return next;
}

PK_Signature_Options PK_Signature_Options::with_deterministic_signature(bool deterministic) {
   BOTAN_STATE_CHECK_MSG(
      !m_deterministic_sig,
      "PK_Signature_Options::with_deterministic_signature cannot specify deterministic signature twice");
   auto next = (*this);
   next.m_deterministic_sig = deterministic;
   return next;
}

PK_Signature_Options PK_Signature_Options::with_der_encoded_signature(bool der) {
   BOTAN_STATE_CHECK_MSG(!m_use_der,
                         "PK_Signature_Options::with_der_encoded_signature cannot specify DER encoding twice");
   auto next = (*this);
   next.m_use_der = der;
   return next;
}

PK_Signature_Options PK_Signature_Options::with_explicit_trailer_field(bool trailer) {
   BOTAN_STATE_CHECK_MSG(
      !m_explicit_trailer_field,
      "PK_Signature_Options::with_explicit_trailer_field cannot specify explicit trailer field twice");
   auto next = (*this);
   next.m_explicit_trailer_field = trailer;
   return next;
}

namespace {

bool provider_is_in_use(const std::optional<std::string>& provider) {
   return provider.has_value() && !provider->empty() && *provider != "base";
}

}  // namespace

bool PK_Signature_Options::using_provider() const {
   note_examined(Option::Provider);
   return provider_is_in_use(m_provider);
}

std::string PK_Signature_Options::hash_function_name() const {
   note_examined(Option::Hash);

   if(m_hash_fn.has_value()) {
      return m_hash_fn.value();
   }

   throw Invalid_State("This signature scheme requires specifying a hash function");
}

uint32_t PK_Signature_Options::options_in_use() const {
   uint32_t in_use = 0;

   auto set_if = [&](bool cond, Option option) {
      if(cond) {
         in_use |= static_cast<uint32_t>(option);
      }
   };

   set_if(m_hash_fn.has_value(), Option::Hash);
   set_if(m_using_prehash, Option::Prehash);
   set_if(m_using_external_prehash, Option::ExternalPrehash);
   set_if(m_padding.has_value(), Option::Padding);
   set_if(m_context.has_value(), Option::Context);
   set_if(provider_is_in_use(m_provider), Option::Provider);
   set_if(m_salt_size.has_value(), Option::SaltSize);
   set_if(m_use_der, Option::DerEncoded);
   set_if(m_deterministic_sig, Option::Deterministic);
   set_if(m_explicit_trailer_field, Option::ExplicitTrailer);

   return in_use;
}

namespace {

/*
* Shared by all of the option types: throw naming each option in the
* unexamined bitmask, using the provided (bit, name) table.
*/
template <typename OptionEnum>
void throw_for_unexamined_options(std::string_view algo_name,
                                  std::string_view option_kind,
                                  uint32_t unexamined,
                                  std::initializer_list<std::pair<OptionEnum, std::string_view>> option_names) {
   if(unexamined == 0) {
      return;
   }

   std::string names;
   for(const auto& [option, name] : option_names) {
      if((unexamined & static_cast<uint32_t>(option)) != 0) {
         if(!names.empty()) {
            names += ", ";
         }
         names += name;
      }
   }

   throw Invalid_Argument(fmt("{} does not support the {} option(s): {}", algo_name, option_kind, names));
}

}  // namespace

void PK_Signature_Options::throw_if_unexamined(std::string_view algo_name) const {
   const uint32_t unexamined = options_in_use() & ~m_examined;

   if(unexamined != 0) {
      throw_for_unexamined_options<Option>(algo_name,
                                           "signature",
                                           unexamined,
                                           {
                                              {Option::Hash, "hash"},
                                              {Option::Prehash, "prehash"},
                                              {Option::Padding, "padding"},
                                              {Option::Context, "context"},
                                              {Option::Provider, "provider"},
                                              {Option::SaltSize, "salt size"},
                                              {Option::DerEncoded, "DER encoding"},
                                              {Option::Deterministic, "deterministic"},
                                              {Option::ExplicitTrailer, "explicit trailer field"},
                                              {Option::ExternalPrehash, "externally computed prehash"},
                                           });
   }
}

std::string PK_Signature_Options::to_string() const {
   std::ostringstream out;

   auto print_str = [&](std::string_view name, std::optional<std::string> val) {
      if(val.has_value()) {
         out << name << "='" << val.value() << "' ";
      }
   };

   // This reads the members directly since formatting the options does not
   // count as the signature scheme having examined them

   print_str("Hash", m_hash_fn);
   print_str("Padding", m_padding);
   print_str("Provider", m_provider);

   if(m_using_prehash) {
      out << "Prehash=" << m_prehash.value_or("default") << " ";
   }
   if(m_using_external_prehash) {
      out << "ExternalPrehash=" << m_external_prehash.value_or("unspecified") << " ";
   }

   if(m_context) {
      out << "Context=" << hex_encode(*m_context) << " ";
   }

   if(m_salt_size) {
      out << "SaltLen=" << *m_salt_size << " ";
   }
   if(m_use_der) {
      out << "DerSignature ";
   }
   if(m_deterministic_sig) {
      out << "Deterministic ";
   }
   if(m_explicit_trailer_field) {
      out << "ExplicitTrailer ";
   }

   return out.str();
}

// PK_Encryption_Options

PK_Encryption_Options::~PK_Encryption_Options() = default;

PK_Encryption_Options PK_Encryption_Options::with_padding(std::string_view padding) {
   BOTAN_STATE_CHECK_MSG(!m_padding.has_value(), "PK_Encryption_Options::with_padding cannot specify padding twice");
   auto next = (*this);
   if(!padding.empty()) {
      next.m_padding = padding;
   }
   return next;
}

PK_Encryption_Options PK_Encryption_Options::with_hash(std::string_view hash) {
   BOTAN_STATE_CHECK_MSG(!m_hash_fn.has_value(), "PK_Encryption_Options::with_hash cannot specify hash twice");
   auto next = (*this);
   if(!hash.empty()) {
      next.m_hash_fn = hash;
   }
   return next;
}

PK_Encryption_Options PK_Encryption_Options::with_mgf1_hash(std::string_view hash) {
   BOTAN_STATE_CHECK_MSG(!m_mgf1_hash_fn.has_value(),
                         "PK_Encryption_Options::with_mgf1_hash cannot specify MGF1 hash twice");
   auto next = (*this);
   if(!hash.empty()) {
      next.m_mgf1_hash_fn = hash;
   }
   return next;
}

PK_Encryption_Options PK_Encryption_Options::with_context(std::span<const uint8_t> context) {
   BOTAN_STATE_CHECK_MSG(!m_context.has_value(), "PK_Encryption_Options::with_context cannot specify context twice");
   auto next = (*this);
   next.m_context = std::vector<uint8_t>(context.begin(), context.end());
   return next;
}

PK_Encryption_Options PK_Encryption_Options::with_context(std::string_view context) {
   return this->with_context(as_span_of_bytes(context));
}

PK_Encryption_Options PK_Encryption_Options::with_provider(std::string_view provider) {
   BOTAN_STATE_CHECK_MSG(provider.empty() || !m_provider.has_value(),
                         "PK_Encryption_Options::with_provider cannot specify provider twice");
   auto next = (*this);
   if(!provider.empty()) {
      next.m_provider = provider;
   }
   return next;
}

bool PK_Encryption_Options::using_provider() const {
   note_examined(Option::Provider);
   return provider_is_in_use(m_provider);
}

std::string PK_Encryption_Options::hash_function_name() const {
   note_examined(Option::Hash);

   if(m_hash_fn.has_value()) {
      return m_hash_fn.value();
   }

   throw Invalid_State("This encryption scheme requires specifying a hash function");
}

uint32_t PK_Encryption_Options::options_in_use() const {
   uint32_t in_use = 0;

   auto set_if = [&](bool cond, Option option) {
      if(cond) {
         in_use |= static_cast<uint32_t>(option);
      }
   };

   set_if(m_padding.has_value(), Option::Padding);
   set_if(m_hash_fn.has_value(), Option::Hash);
   set_if(m_mgf1_hash_fn.has_value(), Option::Mgf1Hash);
   set_if(m_context.has_value(), Option::Context);
   set_if(provider_is_in_use(m_provider), Option::Provider);

   return in_use;
}

void PK_Encryption_Options::throw_if_unexamined(std::string_view algo_name) const {
   const uint32_t unexamined = options_in_use() & ~m_examined;

   if(unexamined != 0) {
      throw_for_unexamined_options<Option>(algo_name,
                                           "encryption",
                                           unexamined,
                                           {
                                              {Option::Padding, "padding"},
                                              {Option::Hash, "hash"},
                                              {Option::Mgf1Hash, "MGF1 hash"},
                                              {Option::Context, "context"},
                                              {Option::Provider, "provider"},
                                           });
   }
}

std::string PK_Encryption_Options::to_string() const {
   std::ostringstream out;

   auto print_str = [&](std::string_view name, const std::optional<std::string>& val) {
      if(val.has_value()) {
         out << name << "='" << val.value() << "' ";
      }
   };

   // Reads the members directly since formatting does not count as examining

   print_str("Padding", m_padding);
   print_str("Hash", m_hash_fn);
   print_str("MGF1Hash", m_mgf1_hash_fn);
   print_str("Provider", m_provider);

   if(m_context) {
      out << "Context=" << hex_encode(*m_context) << " ";
   }

   return out.str();
}

// PK_KEM_Options

PK_KEM_Options::~PK_KEM_Options() = default;

PK_KEM_Options PK_KEM_Options::with_kdf(std::string_view kdf) {
   BOTAN_STATE_CHECK_MSG(!m_kdf.has_value(), "PK_KEM_Options::with_kdf cannot specify KDF twice");
   BOTAN_STATE_CHECK_MSG(!m_raw_shared_key, "PK_KEM_Options::with_kdf cannot be combined with with_raw_shared_key");
   // Silently accepting an empty name would turn a request for a KDF into the raw shared key
   BOTAN_ARG_CHECK(!kdf.empty(), "PK_KEM_Options::with_kdf requires a KDF name");
   auto next = (*this);
   next.m_kdf = kdf;
   return next;
}

PK_KEM_Options PK_KEM_Options::with_raw_shared_key() {
   BOTAN_STATE_CHECK_MSG(!m_raw_shared_key, "PK_KEM_Options::with_raw_shared_key cannot be specified twice");
   BOTAN_STATE_CHECK_MSG(!m_kdf.has_value(), "PK_KEM_Options::with_raw_shared_key cannot be combined with with_kdf");
   auto next = (*this);
   next.m_raw_shared_key = true;
   return next;
}

PK_KEM_Options PK_KEM_Options::with_provider(std::string_view provider) {
   BOTAN_STATE_CHECK_MSG(provider.empty() || !m_provider.has_value(),
                         "PK_KEM_Options::with_provider cannot specify provider twice");
   auto next = (*this);
   if(!provider.empty()) {
      next.m_provider = provider;
   }
   return next;
}

bool PK_KEM_Options::using_provider() const {
   note_examined(Option::Provider);
   return provider_is_in_use(m_provider);
}

uint32_t PK_KEM_Options::options_in_use() const {
   uint32_t in_use = 0;

   auto set_if = [&](bool cond, Option option) {
      if(cond) {
         in_use |= static_cast<uint32_t>(option);
      }
   };

   set_if(m_kdf.has_value(), Option::Kdf);
   set_if(m_raw_shared_key, Option::RawSharedKey);
   set_if(provider_is_in_use(m_provider), Option::Provider);

   return in_use;
}

void PK_KEM_Options::throw_if_unexamined(std::string_view algo_name) const {
   const uint32_t unexamined = options_in_use() & ~m_examined;

   if(unexamined != 0) {
      throw_for_unexamined_options<Option>(algo_name,
                                           "KEM",
                                           unexamined,
                                           {
                                              {Option::Kdf, "KDF"},
                                              {Option::RawSharedKey, "raw shared key"},
                                              {Option::Provider, "provider"},
                                           });
   }
}

std::string PK_KEM_Options::to_string() const {
   std::ostringstream out;

   if(m_kdf) {
      out << "KDF='" << *m_kdf << "' ";
   }
   if(m_raw_shared_key) {
      out << "RawSharedKey ";
   }
   if(m_provider) {
      out << "Provider='" << *m_provider << "' ";
   }

   return out.str();
}

// PK_Key_Agreement_Options

PK_Key_Agreement_Options::~PK_Key_Agreement_Options() = default;

PK_Key_Agreement_Options PK_Key_Agreement_Options::with_kdf(std::string_view kdf) {
   BOTAN_STATE_CHECK_MSG(!m_kdf.has_value(), "PK_Key_Agreement_Options::with_kdf cannot specify KDF twice");
   BOTAN_STATE_CHECK_MSG(!m_raw_shared_key,
                         "PK_Key_Agreement_Options::with_kdf cannot be combined with with_raw_shared_key");
   // Silently accepting an empty name would turn a request for a KDF into the raw agreed value
   BOTAN_ARG_CHECK(!kdf.empty(), "PK_Key_Agreement_Options::with_kdf requires a KDF name");
   auto next = (*this);
   next.m_kdf = kdf;
   return next;
}

PK_Key_Agreement_Options PK_Key_Agreement_Options::with_raw_shared_key() {
   BOTAN_STATE_CHECK_MSG(!m_raw_shared_key, "PK_Key_Agreement_Options::with_raw_shared_key cannot be specified twice");
   BOTAN_STATE_CHECK_MSG(!m_kdf.has_value(),
                         "PK_Key_Agreement_Options::with_raw_shared_key cannot be combined with with_kdf");
   auto next = (*this);
   next.m_raw_shared_key = true;
   return next;
}

PK_Key_Agreement_Options PK_Key_Agreement_Options::with_provider(std::string_view provider) {
   BOTAN_STATE_CHECK_MSG(provider.empty() || !m_provider.has_value(),
                         "PK_Key_Agreement_Options::with_provider cannot specify provider twice");
   auto next = (*this);
   if(!provider.empty()) {
      next.m_provider = provider;
   }
   return next;
}

bool PK_Key_Agreement_Options::using_provider() const {
   note_examined(Option::Provider);
   return provider_is_in_use(m_provider);
}

uint32_t PK_Key_Agreement_Options::options_in_use() const {
   uint32_t in_use = 0;

   auto set_if = [&](bool cond, Option option) {
      if(cond) {
         in_use |= static_cast<uint32_t>(option);
      }
   };

   set_if(m_kdf.has_value(), Option::Kdf);
   set_if(m_raw_shared_key, Option::RawSharedKey);
   set_if(provider_is_in_use(m_provider), Option::Provider);

   return in_use;
}

void PK_Key_Agreement_Options::throw_if_unexamined(std::string_view algo_name) const {
   const uint32_t unexamined = options_in_use() & ~m_examined;

   if(unexamined != 0) {
      throw_for_unexamined_options<Option>(algo_name,
                                           "key agreement",
                                           unexamined,
                                           {
                                              {Option::Kdf, "KDF"},
                                              {Option::RawSharedKey, "raw shared key"},
                                              {Option::Provider, "provider"},
                                           });
   }
}

std::string PK_Key_Agreement_Options::to_string() const {
   std::ostringstream out;

   if(m_kdf) {
      out << "KDF='" << *m_kdf << "' ";
   }
   if(m_raw_shared_key) {
      out << "RawSharedKey ";
   }
   if(m_provider) {
      out << "Provider='" << *m_provider << "' ";
   }

   return out.str();
}

}  // namespace Botan
