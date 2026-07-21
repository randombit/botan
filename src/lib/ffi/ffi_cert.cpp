/*
* (C) 2015,2017,2018 Jack Lloyd
* (C) 2026 Dominik Schricker
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>

#include <botan/assert.h>
#include <botan/dns_name.h>
#include <botan/email.h>
#include <botan/ipv4_address.h>
#include <botan/ipv6_address.h>
#include <botan/uri.h>
#include <botan/internal/ffi_cert.h>
#include <botan/internal/ffi_pkey.h>
#include <botan/internal/ffi_rng.h>
#include <botan/internal/ffi_util.h>
#include <memory>

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   #include <botan/data_src.h>
   #include <botan/x509_crl.h>
   #include <botan/x509_ext.h>
   #include <botan/x509cert.h>
   #include <botan/x509path.h>
   #include <botan/internal/ffi_mp.h>
   #include <botan/internal/ffi_oid.h>
   #include <botan/internal/stl_util.h>
#endif

#if defined(BOTAN_HAS_X509_CERTIFICATES)

namespace Botan_FFI {

namespace {

/**
 * As specified in RFC 5280 Section 4.2.1.6. alternative names essentially are a
 * collection of GeneralNames. This allows mapping a single entry of @p altnames
 * to a GeneralName by its @p index. If the index is out of range, std::nullopt
 * is returned.
 *
 * NOTE: if the set of alternative name types handled here is extended,
 *       count_general_names_in() must be updated accordingly!
 */
std::optional<Botan::GeneralName> extract_general_name_at(const Botan::AlternativeName& altnames, size_t index) {
   if(index < altnames.email_addresses().size()) {
      auto itr = altnames.email_addresses().begin();
      std::advance(itr, index);
      return Botan::GeneralName::email(itr->to_string());
   }
   index -= altnames.email_addresses().size();

   if(index < altnames.dns_names().size()) {
      auto itr = altnames.dns_names().begin();
      std::advance(itr, index);
      return Botan::GeneralName::_dns_san_value(itr->to_string());
   }
   index -= altnames.dns_names().size();

   if(index < altnames.directory_names().size()) {
      auto itr = altnames.directory_names().begin();
      std::advance(itr, index);
      return Botan::GeneralName::directory_name(*itr);
   }
   index -= altnames.directory_names().size();

   if(index < altnames.uri_names().size()) {
      auto itr = altnames.uri_names().begin();
      std::advance(itr, index);
      return Botan::GeneralName::_uri_san_value(itr->original_input());
   }
   index -= altnames.uri_names().size();

   if(index < altnames.ipv4_addresses().size()) {
      auto itr = altnames.ipv4_addresses().begin();
      std::advance(itr, index);
      return Botan::GeneralName::ipv4_address(*itr);
   }
   index -= altnames.ipv4_addresses().size();

   if(index < altnames.ipv6_addresses().size()) {
      auto itr = altnames.ipv6_addresses().begin();
      std::advance(itr, index);
      return Botan::GeneralName::ipv6_address(*itr);
   }

   return std::nullopt;
}

/**
 * Counts the total number of GeneralNames contained in the given
 * AlternativeName @p alt_names.
 *
 * NOTE: if the set of alternative name types handled here is extended,
 *       extract_general_name_at() must be updated accordingly!
 */
size_t count_general_names_in(const Botan::AlternativeName& alt_names) {
   return alt_names.email_addresses().size() + alt_names.dns_names().size() + alt_names.directory_names().size() +
          alt_names.uri_names().size() + alt_names.ipv4_addresses().size() + alt_names.ipv6_addresses().size();
}

std::optional<botan_x509_general_name_types> to_botan_x509_general_name_types(Botan::GeneralName::NameType gn_type) {
   using Type = Botan::GeneralName::NameType;
   switch(gn_type) {
      case Type::Unknown:
         return std::nullopt;
      case Type::RFC822:
         return BOTAN_X509_EMAIL_ADDRESS;
      case Type::DNS:
         return BOTAN_X509_DNS_NAME;
      case Type::URI:
         return BOTAN_X509_URI;
      case Type::DN:
         return BOTAN_X509_DIRECTORY_NAME;
      case Type::IPv4:
      case Type::IPv6:
         return BOTAN_X509_IP_ADDRESS;
      case Type::Other:
         return BOTAN_X509_OTHER_NAME;
   }

   BOTAN_ASSERT_UNREACHABLE();
}

/**
 * Given some enumerator-style function @p fn, count how many values it can
 * produce before returning BOTAN_FFI_ERROR_OUT_OF_RANGE. If the first call to
 * @p fn returns BOTAN_FFI_ERROR_NO_VALUE, zero is written to @p count.
 *
 * If this function returns BOTAN_FFI_SUCCESS, @p count contains the number of
 * values that can be enumerated. Otherwise, the value of @p count is undefined.
 */
template <std::invocable<size_t> EnumeratorT>
int enumerator_count_values(size_t* count, EnumeratorT fn) {
   if(Botan::any_null_pointers(count)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   *count = 0;
   for(;; ++(*count)) {
      const auto rc = fn(*count);
      switch(rc) {
         case BOTAN_FFI_ERROR_NO_VALUE:
         case BOTAN_FFI_ERROR_OUT_OF_RANGE:
            // hit the end of the enumeration
            return BOTAN_FFI_SUCCESS;
         case BOTAN_FFI_SUCCESS:
            // got a value, continue counting
            break;
         default:
            // unexpected error from enumerator function
            return rc;
      }
   }
}

std::chrono::system_clock::time_point timepoint_from_timestamp(uint64_t time_since_epoch) {
   return std::chrono::system_clock::time_point(std::chrono::seconds(time_since_epoch));
}

std::string default_from_ptr(const char* value) {
   std::string ret;
   if(!Botan::any_null_pointers(value)) {
      ret = value;
   }
   return ret;
}

std::optional<std::string> optional_from_ptr(const char* value) {
   if(!Botan::any_null_pointers(value)) {
      return std::string(value);
   }
   return std::nullopt;
}

Botan::X509_Time time_from_timestamp(uint64_t time_since_epoch) {
   return Botan::X509_Time(timepoint_from_timestamp(time_since_epoch));
}

   #if defined(BOTAN_HAS_X509_CERTIFICATES)
      #define X509_CERT_BUILDER_ADD_STRING(FIELD_NAME)                                                        \
         int botan_x509_cert_builder_add_##FIELD_NAME(botan_x509_cert_builder_t builder, const char* value) { \
            if(Botan::any_null_pointers(value)) {                                                             \
               return BOTAN_FFI_ERROR_NULL_POINTER;                                                           \
            }                                                                                                 \
            return BOTAN_FFI_VISIT(builder, [=](auto& b) { b.add_##FIELD_NAME(value); });                     \
         }
   #else
      #define X509_CERT_BUILDER_ADD_STRING(FIELD_NAME)                                                        \
         int botan_x509_cert_builder_add_##FIELD_NAME(botan_x509_cert_builder_t builder, const char* value) { \
            if(Botan::any_null_pointers(value)) {                                                             \
               return BOTAN_FFI_ERROR_NULL_POINTER;                                                           \
            }                                                                                                 \
            BOTAN_UNUSED(builder);                                                                            \
            return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;                                                           \
         }
   #endif

   #if defined(BOTAN_HAS_X509_CERTIFICATES)
      #define X509_CERT_BUILDER_ADD_TYPED(FIELD_NAME, TYPE_NAME)                                              \
         int botan_x509_cert_builder_add_##FIELD_NAME(botan_x509_cert_builder_t builder, const char* value) { \
            if(Botan::any_null_pointers(value)) {                                                             \
               return BOTAN_FFI_ERROR_NULL_POINTER;                                                           \
            }                                                                                                 \
            return BOTAN_FFI_VISIT(builder, [=](auto& b) {                                                    \
               std::optional<TYPE_NAME> v = TYPE_NAME::from_string(value);                                    \
               if(!v.has_value()) {                                                                           \
                  return BOTAN_FFI_ERROR_BAD_PARAMETER;                                                       \
               }                                                                                              \
               b.add_##FIELD_NAME(v.value());                                                                 \
               return BOTAN_FFI_SUCCESS;                                                                      \
            });                                                                                               \
         }
   #else
      #define X509_CERT_BUILDER_ADD_TYPED(FIELD_NAME, TYPE_NAME)                                              \
         int botan_x509_cert_builder_add_##FIELD_NAME(botan_x509_cert_builder_t builder, const char* value) { \
            if(Botan::any_null_pointers(value)) {                                                             \
               return BOTAN_FFI_ERROR_NULL_POINTER;                                                           \
            }                                                                                                 \
            BOTAN_UNUSED(builder);                                                                            \
            return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;                                                           \
         }
   #endif

}  // namespace

}  // namespace Botan_FFI

#endif

extern "C" {

using namespace Botan_FFI;

int botan_x509_cert_load_file(botan_x509_cert_t* cert_obj, const char* cert_path) {
   if(Botan::any_null_pointers(cert_obj, cert_path)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

   return ffi_guard_thunk(__func__, [=]() -> int {
      auto c = std::make_unique<Botan::X509_Certificate>(cert_path);
      return ffi_new_object(cert_obj, std::move(c));
   });

#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_dup(botan_x509_cert_t* cert_obj, botan_x509_cert_t cert) {
   if(cert_obj == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

   return ffi_guard_thunk(__func__, [=]() -> int {
      auto c = std::make_unique<Botan::X509_Certificate>(safe_get(cert));
      return ffi_new_object(cert_obj, std::move(c));
   });

#else
   BOTAN_UNUSED(cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_load(botan_x509_cert_t* cert_obj, const uint8_t cert_bits[], size_t cert_bits_len) {
   if(Botan::any_null_pointers(cert_obj, cert_bits)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::DataSource_Memory bits(cert_bits, cert_bits_len);
      auto c = std::make_unique<Botan::X509_Certificate>(bits);
      return ffi_new_object(cert_obj, std::move(c));
   });
#else
   BOTAN_UNUSED(cert_bits_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}
}

namespace {

#if defined(BOTAN_HAS_X509_CERTIFICATES)

int botan_x509_object_view_value(const Botan::X509_Object& object,
                                 botan_x509_value_type value_type,
                                 size_t index,
                                 botan_view_ctx ctx,
                                 botan_view_str_fn view_fn) {
   if(index != 0) {
      // As of now there are no multi-value generic string entries.
      return BOTAN_FFI_ERROR_OUT_OF_RANGE;
   }

   auto view = [=](const std::string& value) { return invoke_view_callback(view_fn, ctx, value); };

   switch(value_type) {
      case BOTAN_X509_PEM_ENCODING:
         return view(object.PEM_encode());
      default:
         BOTAN_ASSERT_UNREACHABLE(); /* called with unexpected (non-generic) value_type */
   }
}

int botan_x509_object_view_value(const Botan::X509_Object& object,
                                 botan_x509_value_type value_type,
                                 size_t index,
                                 botan_view_ctx ctx,
                                 botan_view_bin_fn view_fn) {
   if(index != 0) {
      // As of now there are no multi-value generic binary entries.
      return BOTAN_FFI_ERROR_OUT_OF_RANGE;
   }

   auto view = [=](std::span<const uint8_t> value) { return invoke_view_callback(view_fn, ctx, value); };

   switch(value_type) {
      case BOTAN_X509_TBS_DATA_BITS:
         return view(object.tbs_data());
      case BOTAN_X509_SIGNATURE_SCHEME_BITS:
         return view(object.signature_algorithm().BER_encode());
      case BOTAN_X509_SIGNATURE_BITS:
         return view(object.signature());
      case BOTAN_X509_DER_ENCODING:
         return view(object.BER_encode());
      default:
         BOTAN_ASSERT_UNREACHABLE(); /* called with unexpected (non-generic) value_type */
   }
}

#endif

}  // namespace

extern "C" {

int botan_x509_cert_view_binary_values(botan_x509_cert_t cert,
                                       botan_x509_value_type value_type,
                                       size_t index,
                                       botan_view_ctx ctx,
                                       botan_view_bin_fn view_fn) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   if(index != 0) {
      // As of now there are no multi-value binary entries.
      return BOTAN_FFI_ERROR_OUT_OF_RANGE;
   }

   auto view = [=](std::span<const uint8_t> value) -> int {
      if(value.empty()) {
         return BOTAN_FFI_ERROR_NO_VALUE;
      } else {
         return invoke_view_callback(view_fn, ctx, value);
      }
   };

   return BOTAN_FFI_VISIT(cert, [=](const Botan::X509_Certificate& c) -> int {
      switch(value_type) {
         case BOTAN_X509_SERIAL_NUMBER:
            return view(c.serial_number());
         case BOTAN_X509_SUBJECT_DN_BITS:
            return view(c.raw_subject_dn());
         case BOTAN_X509_ISSUER_DN_BITS:
            return view(c.raw_issuer_dn());
         case BOTAN_X509_SUBJECT_KEY_IDENTIFIER:
            return view(c.subject_key_id());
         case BOTAN_X509_AUTHORITY_KEY_IDENTIFIER:
            return view(c.authority_key_id());
         case BOTAN_X509_PUBLIC_KEY_PKCS8_BITS:
            return view(c.subject_public_key_info());

         case BOTAN_X509_TBS_DATA_BITS:
         case BOTAN_X509_SIGNATURE_SCHEME_BITS:
         case BOTAN_X509_SIGNATURE_BITS:
         case BOTAN_X509_DER_ENCODING:
            return botan_x509_object_view_value(c, value_type, index, ctx, view_fn);

         case BOTAN_X509_PEM_ENCODING:
         case BOTAN_X509_CRL_DISTRIBUTION_URLS:
         case BOTAN_X509_OCSP_RESPONDER_URLS:
         case BOTAN_X509_CA_ISSUERS_URLS:
            return BOTAN_FFI_ERROR_NO_VALUE;
      }

      return BOTAN_FFI_ERROR_BAD_PARAMETER;
   });
#else
   BOTAN_UNUSED(cert, value_type, index, ctx, view_fn);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_view_binary_values_count(botan_x509_cert_t cert, botan_x509_value_type value_type, size_t* count) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return enumerator_count_values(count, [=](size_t index) {
      return botan_x509_cert_view_binary_values(
         cert, value_type, index, nullptr, [](auto, auto, auto) -> int { return BOTAN_FFI_SUCCESS; });
   });
#else
   BOTAN_UNUSED(cert, value_type, count);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_view_string_values(botan_x509_cert_t cert,
                                       botan_x509_value_type value_type,
                                       size_t index,
                                       botan_view_ctx ctx,
                                       botan_view_str_fn view_fn) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   auto enumerate_uris = [view_fn, ctx](const std::vector<Botan::URI>& values, size_t idx) -> int {
      if(idx >= values.size()) {
         return BOTAN_FFI_ERROR_OUT_OF_RANGE;
      } else {
         return invoke_view_callback(view_fn, ctx, values[idx].original_input());
      }
   };

   return BOTAN_FFI_VISIT(cert, [=](const Botan::X509_Certificate& c) -> int {
      switch(value_type) {
         case BOTAN_X509_CRL_DISTRIBUTION_URLS:
            return enumerate_uris(c.crl_distribution_point_uris(), index);
         case BOTAN_X509_OCSP_RESPONDER_URLS:
            return enumerate_uris(c.ocsp_responder_uris(), index);
         case BOTAN_X509_CA_ISSUERS_URLS:
            return enumerate_uris(c.ca_issuer_uris(), index);
         case BOTAN_X509_PEM_ENCODING:
            return botan_x509_object_view_value(c, value_type, index, ctx, view_fn);

         case BOTAN_X509_SERIAL_NUMBER:
         case BOTAN_X509_SUBJECT_DN_BITS:
         case BOTAN_X509_ISSUER_DN_BITS:
         case BOTAN_X509_SUBJECT_KEY_IDENTIFIER:
         case BOTAN_X509_AUTHORITY_KEY_IDENTIFIER:
         case BOTAN_X509_PUBLIC_KEY_PKCS8_BITS:
         case BOTAN_X509_TBS_DATA_BITS:
         case BOTAN_X509_SIGNATURE_SCHEME_BITS:
         case BOTAN_X509_SIGNATURE_BITS:
         case BOTAN_X509_DER_ENCODING:
            return BOTAN_FFI_ERROR_NO_VALUE;
      }

      return BOTAN_FFI_ERROR_BAD_PARAMETER;
   });
#else
   BOTAN_UNUSED(cert, value_type, index, ctx, view_fn);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_view_string_values_count(botan_x509_cert_t cert, botan_x509_value_type value_type, size_t* count) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return enumerator_count_values(count, [=](size_t index) {
      return botan_x509_cert_view_string_values(
         cert, value_type, index, nullptr, [](auto, auto, auto) -> int { return BOTAN_FFI_SUCCESS; });
   });
#else
   BOTAN_UNUSED(cert, value_type, count);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_is_ca(botan_x509_cert_t cert) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { return c.is_CA_cert() ? 1 : 0; });
#else
   BOTAN_UNUSED(cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_path_length_constraint(botan_x509_cert_t cert, size_t* path_limit) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) -> int {
      if(Botan::any_null_pointers(path_limit)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      if(const auto path_len = c.path_length_constraint()) {
         *path_limit = path_len.value();
         return BOTAN_FFI_SUCCESS;
      } else {
         return BOTAN_FFI_ERROR_NO_VALUE;
      }
   });
#else
   BOTAN_UNUSED(cert, path_limit);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_public_key(botan_x509_cert_t cert, botan_pubkey_t* key) {
   if(key == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   *key = nullptr;

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto public_key = safe_get(cert).subject_public_key();
      return ffi_new_object(key, std::move(public_key));
   });
#else
   BOTAN_UNUSED(cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_issuer_dn(
   botan_x509_cert_t cert, const char* key, size_t index, uint8_t out[], size_t* out_len) {
   if(key == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) -> int {
      auto issuer_info = c.issuer_info(key);
      if(index < issuer_info.size()) {
         // TODO(Botan4) change the type of out and remove this cast
         return write_str_output(reinterpret_cast<char*>(out), out_len, c.issuer_info(key).at(index));
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;  // TODO(Botan4): use BOTAN_FFI_ERROR_OUT_OF_RANGE
      }
   });
#else
   BOTAN_UNUSED(cert, key, index, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_issuer_dn_count(botan_x509_cert_t cert, const char* key, size_t* count) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) -> int {
      if(Botan::any_null_pointers(key, count)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      *count = c.issuer_info(key).size();
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(cert, key, count);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_subject_dn(
   botan_x509_cert_t cert, const char* key, size_t index, uint8_t out[], size_t* out_len) {
   if(key == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) -> int {
      auto subject_info = c.subject_info(key);
      if(index < subject_info.size()) {
         // TODO(Botan4) change the type of out and remove this cast
         return write_str_output(reinterpret_cast<char*>(out), out_len, c.subject_info(key).at(index));
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;  // TODO(Botan4): use BOTAN_FFI_ERROR_OUT_OF_RANGE
      }
   });
#else
   BOTAN_UNUSED(cert, key, index, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_subject_dn_count(botan_x509_cert_t cert, const char* key, size_t* count) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) -> int {
      if(Botan::any_null_pointers(key, count)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      *count = c.subject_info(key).size();
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(cert, key, count);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_to_string(botan_x509_cert_t cert, char out[], size_t* out_len) {
   return copy_view_str(reinterpret_cast<uint8_t*>(out), out_len, botan_x509_cert_view_as_string, cert);
}

int botan_x509_cert_view_as_string(botan_x509_cert_t cert, botan_view_ctx ctx, botan_view_str_fn view) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { return invoke_view_callback(view, ctx, c.to_string()); });
#else
   BOTAN_UNUSED(cert, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_allowed_usage(botan_x509_cert_t cert, unsigned int key_usage) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) -> int {
      const Botan::Key_Constraints k = static_cast<Botan::Key_Constraints>(key_usage);
      if(c.allowed_usage(k)) {
         return BOTAN_FFI_SUCCESS;
      }
      return 1;
   });
#else
   BOTAN_UNUSED(cert, key_usage);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_allowed_extended_usage_str(botan_x509_cert_t cert, const char* oid) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) -> int {
      if(Botan::any_null_pointers(oid)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      return c.has_ex_constraint(oid) ? 1 : 0;
   });
#else
   BOTAN_UNUSED(cert, oid);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_allowed_extended_usage_oid(botan_x509_cert_t cert, botan_asn1_oid_t oid) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) -> int { return c.has_ex_constraint(safe_get(oid)) ? 1 : 0; });
#else
   BOTAN_UNUSED(cert, oid);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_destroy(botan_x509_cert_t cert) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(cert);
#else
   BOTAN_UNUSED(cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_time_starts(botan_x509_cert_t cert, char out[], size_t* out_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert,
                          [=](const auto& c) { return write_str_output(out, out_len, c.not_before().to_string()); });
#else
   BOTAN_UNUSED(cert, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_time_expires(botan_x509_cert_t cert, char out[], size_t* out_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert,
                          [=](const auto& c) { return write_str_output(out, out_len, c.not_after().to_string()); });
#else
   BOTAN_UNUSED(cert, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_not_before(botan_x509_cert_t cert, uint64_t* time_since_epoch) {
   if(time_since_epoch == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { *time_since_epoch = c.not_before().time_since_epoch(); });
#else
   BOTAN_UNUSED(cert, time_since_epoch);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_not_after(botan_x509_cert_t cert, uint64_t* time_since_epoch) {
   if(time_since_epoch == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { *time_since_epoch = c.not_after().time_since_epoch(); });
#else
   BOTAN_UNUSED(cert, time_since_epoch);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_serial_number(botan_x509_cert_t cert, uint8_t out[], size_t* out_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { return write_vec_output(out, out_len, c.serial_number()); });
#else
   BOTAN_UNUSED(cert, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_serial_number(botan_x509_cert_t cert, botan_mp_t* serial_number) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const Botan::X509_Certificate& c) {
      if(Botan::any_null_pointers(serial_number)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      auto serial_bn = c.serial().to_bigint();
      return ffi_new_object(serial_number, std::make_unique<Botan::BigInt>(std::move(serial_bn)));
   });
#else
   BOTAN_UNUSED(cert, serial_number);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_fingerprint(botan_x509_cert_t cert, const char* hash, uint8_t out[], size_t* out_len) {
   if(hash == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   // TODO(Botan4) change the type of out and remove this cast

   return BOTAN_FFI_VISIT(cert, [=](const auto& c) {
      return write_str_output(reinterpret_cast<char*>(out), out_len, c.fingerprint(hash));
   });
#else
   BOTAN_UNUSED(cert, hash, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_authority_key_id(botan_x509_cert_t cert, uint8_t out[], size_t* out_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { return write_vec_output(out, out_len, c.authority_key_id()); });
#else
   BOTAN_UNUSED(cert, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_subject_key_id(botan_x509_cert_t cert, uint8_t out[], size_t* out_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { return write_vec_output(out, out_len, c.subject_key_id()); });
#else
   BOTAN_UNUSED(cert, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_public_key_bits(botan_x509_cert_t cert, uint8_t out[], size_t* out_len) {
   return copy_view_bin(out, out_len, botan_x509_cert_view_public_key_bits, cert);
}

int botan_x509_cert_view_public_key_bits(botan_x509_cert_t cert, botan_view_ctx ctx, botan_view_bin_fn view) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert,
                          [=](const auto& c) { return invoke_view_callback(view, ctx, c.subject_public_key_bits()); });
#else
   BOTAN_UNUSED(cert, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_general_name_get_type(botan_x509_general_name_t name, unsigned int* type) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(name, [=](const Botan::GeneralName& n) {
      if(Botan::any_null_pointers(type)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      const auto mapped_type = to_botan_x509_general_name_types(n.type_code());
      if(!mapped_type.has_value()) {
         return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE;
      }

      *type = mapped_type.value();
      if(*type == BOTAN_X509_OTHER_NAME /* ... viewing of other-names not supported */) {
         return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE;
      }

      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(name, type);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_general_name_view_string_value(botan_x509_general_name_t name,
                                              botan_view_ctx ctx,
                                              botan_view_str_fn view) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(name, [=](const Botan::GeneralName& n) -> int {
      const auto type = to_botan_x509_general_name_types(n.type_code());
      if(!type) {
         return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE;
      }

      if(type != BOTAN_X509_EMAIL_ADDRESS && type != BOTAN_X509_DNS_NAME && type != BOTAN_X509_URI &&
         type != BOTAN_X509_IP_ADDRESS) {
         return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE;
      }

      return invoke_view_callback(view, ctx, n.name());
   });
#else
   BOTAN_UNUSED(name, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_general_name_view_binary_value(botan_x509_general_name_t name,
                                              botan_view_ctx ctx,
                                              botan_view_bin_fn view) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(name, [=](const Botan::GeneralName& n) -> int {
      const auto type = to_botan_x509_general_name_types(n.type_code());
      if(!type) {
         return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE;
      }

      if(type != BOTAN_X509_DIRECTORY_NAME && type != BOTAN_X509_IP_ADDRESS) {
         return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE;
      }

      return invoke_view_callback(view, ctx, n.binary_name());
   });
#else
   BOTAN_UNUSED(name, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_general_name_destroy(botan_x509_general_name_t name) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(name);
#else
   BOTAN_UNUSED(name);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_permitted_name_constraints(botan_x509_cert_t cert,
                                               size_t index,
                                               botan_x509_general_name_t* constraint) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const Botan::X509_Certificate& c) {
      if(Botan::any_null_pointers(constraint)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      const auto& constraints = c.name_constraints().permitted();
      if(index >= constraints.size()) {
         return BOTAN_FFI_ERROR_OUT_OF_RANGE;
      }

      return ffi_new_object(constraint, std::make_unique<Botan::GeneralName>(constraints[index].base()));
   });
#else
   BOTAN_UNUSED(cert, index, constraint);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_permitted_name_constraints_count(botan_x509_cert_t cert, size_t* count) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   if(Botan::any_null_pointers(count)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { *count = c.name_constraints().permitted().size(); });
#else
   BOTAN_UNUSED(cert, count);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_excluded_name_constraints(botan_x509_cert_t cert,
                                              size_t index,
                                              botan_x509_general_name_t* constraint) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const Botan::X509_Certificate& c) {
      if(Botan::any_null_pointers(constraint)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      const auto& constraints = c.name_constraints().excluded();
      if(index >= constraints.size()) {
         return BOTAN_FFI_ERROR_OUT_OF_RANGE;
      }

      return ffi_new_object(constraint, std::make_unique<Botan::GeneralName>(constraints[index].base()));
   });
#else
   BOTAN_UNUSED(cert, index, constraint);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_excluded_name_constraints_count(botan_x509_cert_t cert, size_t* count) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   if(Botan::any_null_pointers(count)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { *count = c.name_constraints().excluded().size(); });
#else
   BOTAN_UNUSED(cert, count);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_subject_alternative_names(botan_x509_cert_t cert,
                                              size_t index,
                                              botan_x509_general_name_t* alt_name) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const Botan::X509_Certificate& c) {
      if(Botan::any_null_pointers(alt_name)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      if(!c.v3_extensions().extension_set(Botan::OID::from_string("X509v3.SubjectAlternativeName"))) {
         return BOTAN_FFI_ERROR_NO_VALUE;
      }

      if(auto name = extract_general_name_at(c.subject_alt_name(), index)) {
         return ffi_new_object(alt_name, std::make_unique<Botan::GeneralName>(std::move(name).value()));
      }

      return BOTAN_FFI_ERROR_OUT_OF_RANGE;
   });
#else
   BOTAN_UNUSED(cert, index, alt_name);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_subject_alternative_names_count(botan_x509_cert_t cert, size_t* count) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   if(Botan::any_null_pointers(count)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(
      cert, [=](const Botan::X509_Certificate& c) { *count = count_general_names_in(c.subject_alt_name()); });
#else
   BOTAN_UNUSED(cert, count);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_issuer_alternative_names(botan_x509_cert_t cert,
                                             size_t index,
                                             botan_x509_general_name_t* alt_name) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const Botan::X509_Certificate& c) {
      if(Botan::any_null_pointers(alt_name)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      if(!c.v3_extensions().extension_set(Botan::OID::from_string("X509v3.IssuerAlternativeName"))) {
         return BOTAN_FFI_ERROR_NO_VALUE;
      }

      if(auto name = extract_general_name_at(c.issuer_alt_name(), index)) {
         return ffi_new_object(alt_name, std::make_unique<Botan::GeneralName>(std::move(name).value()));
      }

      return BOTAN_FFI_ERROR_OUT_OF_RANGE;
   });
#else
   BOTAN_UNUSED(cert, index, alt_name);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_issuer_alternative_names_count(botan_x509_cert_t cert, size_t* count) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   if(Botan::any_null_pointers(count)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(
      cert, [=](const Botan::X509_Certificate& c) { *count = count_general_names_in(c.issuer_alt_name()); });
#else
   BOTAN_UNUSED(cert, count);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_hostname_match(botan_x509_cert_t cert, const char* hostname) {
   if(hostname == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { return c.matches_dns_name(hostname) ? 0 : -1; });
#else
   BOTAN_UNUSED(cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_verify(int* result_code,
                           botan_x509_cert_t cert,
                           const botan_x509_cert_t* intermediates,
                           size_t intermediates_len,
                           const botan_x509_cert_t* trusted,
                           size_t trusted_len,
                           const char* trusted_path,
                           size_t required_strength,
                           const char* hostname_cstr,
                           uint64_t reference_time) {
   if(required_strength == 0) {
      required_strength = 110;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      const std::string hostname((hostname_cstr == nullptr) ? "" : hostname_cstr);
      const Botan::Usage_Type usage = Botan::Usage_Type::UNSPECIFIED;
      const auto validation_time = reference_time == 0
                                      ? std::chrono::system_clock::now()
                                      : std::chrono::system_clock::from_time_t(static_cast<time_t>(reference_time));

      if(intermediates_len > 0 && intermediates == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }
      if(trusted_len > 0 && trusted == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      std::vector<Botan::X509_Certificate> end_certs;
      end_certs.push_back(safe_get(cert));
      for(size_t i = 0; i != intermediates_len; ++i) {
         end_certs.push_back(safe_get(intermediates[i]));
      }

      std::unique_ptr<Botan::Certificate_Store> trusted_from_path;
      std::unique_ptr<Botan::Certificate_Store_In_Memory> trusted_extra;
      std::vector<Botan::Certificate_Store*> trusted_roots;

      if(trusted_path != nullptr && *trusted_path != 0) {
         trusted_from_path = std::make_unique<Botan::Certificate_Store_In_Memory>(trusted_path);
         trusted_roots.push_back(trusted_from_path.get());
      }

      if(trusted_len > 0) {
         trusted_extra = std::make_unique<Botan::Certificate_Store_In_Memory>();
         for(size_t i = 0; i != trusted_len; ++i) {
            trusted_extra->add_certificate(safe_get(trusted[i]));
         }
         trusted_roots.push_back(trusted_extra.get());
      }

      const Botan::Path_Validation_Restrictions restrictions(false, required_strength);

      auto validation_result =
         Botan::x509_path_validate(end_certs, restrictions, trusted_roots, hostname, usage, validation_time);

      if(result_code != nullptr) {
         *result_code = static_cast<int>(validation_result.result());
      }

      if(validation_result.successful_validation()) {
         return 0;
      } else {
         return 1;
      }
   });
#else
   BOTAN_UNUSED(result_code, cert, intermediates, intermediates_len, trusted);
   BOTAN_UNUSED(trusted_len, trusted_path, hostname_cstr, reference_time);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

const char* botan_x509_cert_validation_status(int code) {
   if(code < 0) {
      return nullptr;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   const Botan::Certificate_Status_Code sc = static_cast<Botan::Certificate_Status_Code>(code);
   return Botan::to_string(sc);
#else
   return nullptr;
#endif
}

int botan_x509_cert_builder_destroy(botan_x509_cert_builder_t builder) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(builder);
#else
   BOTAN_UNUSED(builder);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_builder_create(botan_x509_cert_builder_t* builder_obj) {
   if(Botan::any_null_pointers(builder_obj)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto b = std::make_unique<Botan::CertificateParametersBuilder>();
      return ffi_new_object(builder_obj, std::move(b));
   });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

X509_CERT_BUILDER_ADD_STRING(common_name)
X509_CERT_BUILDER_ADD_STRING(country)
X509_CERT_BUILDER_ADD_STRING(organization)
X509_CERT_BUILDER_ADD_STRING(organizational_unit)
X509_CERT_BUILDER_ADD_STRING(locality)
X509_CERT_BUILDER_ADD_STRING(state)
X509_CERT_BUILDER_ADD_STRING(serial_number)
X509_CERT_BUILDER_ADD_STRING(xmpp)

X509_CERT_BUILDER_ADD_TYPED(email, Botan::EmailAddress)
X509_CERT_BUILDER_ADD_TYPED(uri, Botan::URI)
X509_CERT_BUILDER_ADD_TYPED(dns, Botan::DNSName)
X509_CERT_BUILDER_ADD_TYPED(ipv4, Botan::IPv4Address)
X509_CERT_BUILDER_ADD_TYPED(ipv6, Botan::IPv6Address)

int botan_x509_cert_builder_add_allowed_usage(botan_x509_cert_builder_t builder, uint32_t usage) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(builder, [=](auto& b) { b.add_allowed_usage(Botan::Key_Constraints(usage)); });
#else
   BOTAN_UNUSED(builder, usage);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_builder_add_allowed_extended_usage(botan_x509_cert_builder_t builder, botan_asn1_oid_t oid) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(builder, [=](auto& b) -> int {
      b.add_allowed_extended_usage(safe_get(oid));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(builder, oid);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_builder_set_as_ca_certificate(botan_x509_cert_builder_t builder, size_t* limit) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(builder, [=](auto& b) {
      std::optional<size_t> lim;
      if(limit != nullptr) {
         lim = *limit;
      }
      b.set_as_ca_certificate(lim);
   });
#else
   BOTAN_UNUSED(builder, limit);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_builder_into_self_signed_cert(botan_x509_cert_t* cert_obj,
                                                  botan_x509_cert_builder_t builder,
                                                  botan_privkey_t key,
                                                  botan_rng_t rng,
                                                  uint64_t not_before,
                                                  uint64_t not_after,
                                                  const botan_mp_t* serial_number,
                                                  const char* hash_fn,
                                                  const char* padding) {
   if(Botan::any_null_pointers(cert_obj)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto hash_fn_ = optional_from_ptr(hash_fn);
      auto padding_ = optional_from_ptr(padding);
      std::optional<Botan::BigInt> serial;
      if(serial_number != nullptr) {
         serial = safe_get(*serial_number);
      }

      std::unique_ptr<Botan::X509_Certificate> cert = std::make_unique<Botan::X509_Certificate>(
         safe_get(builder).into_self_signed_cert(timepoint_from_timestamp(not_before),
                                                 timepoint_from_timestamp(not_after),
                                                 safe_get(key),
                                                 safe_get(rng),
                                                 serial,
                                                 hash_fn_,
                                                 padding_));

      return ffi_new_object(cert_obj, std::move(cert));
   });
#else
   BOTAN_UNUSED(builder, key, rng, not_before, not_after, hash_fn, padding);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_builder_into_cert(botan_x509_cert_t* cert_obj,
                                      botan_x509_cert_builder_t builder,
                                      botan_x509_cert_t ca_cert,
                                      botan_privkey_t ca_key,
                                      botan_privkey_t key,
                                      botan_rng_t rng,
                                      uint64_t not_before,
                                      uint64_t not_after,
                                      const botan_mp_t* serial_number,
                                      const char* hash_fn,
                                      const char* padding) {
   if(Botan::any_null_pointers(cert_obj)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto hash_fn_ = optional_from_ptr(hash_fn);
      auto padding_ = optional_from_ptr(padding);
      std::optional<Botan::BigInt> serial;
      if(serial_number != nullptr) {
         serial = safe_get(*serial_number);
      }

      std::unique_ptr<Botan::X509_Certificate> cert =
         std::make_unique<Botan::X509_Certificate>(safe_get(builder).into_cert(timepoint_from_timestamp(not_before),
                                                                               timepoint_from_timestamp(not_after),
                                                                               safe_get(ca_cert),
                                                                               safe_get(ca_key),
                                                                               safe_get(key),
                                                                               safe_get(rng),
                                                                               serial,
                                                                               hash_fn_,
                                                                               padding_));

      return ffi_new_object(cert_obj, std::move(cert));
   });
#else
   BOTAN_UNUSED(builder, ca_cert, ca_key, key, rng, not_before, not_after, hash_fn, padding);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_builder_into_pkcs10_req(botan_x509_pkcs10_req_t* req_obj,
                                            botan_x509_cert_builder_t builder,
                                            botan_privkey_t key,
                                            botan_rng_t rng,
                                            const char* hash_fn,
                                            const char* padding,
                                            const char* challenge_password) {
   if(Botan::any_null_pointers(req_obj)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto req = std::make_unique<Botan::PKCS10_Request>(
         safe_get(builder).into_pkcs10_request(safe_get(key),
                                               safe_get(rng),
                                               optional_from_ptr(hash_fn),
                                               optional_from_ptr(padding),
                                               optional_from_ptr(challenge_password)));
      return ffi_new_object(req_obj, std::move(req));
   });
#else
   BOTAN_UNUSED(builder, key, rng, padding, hash_fn, challenge_password);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_pkcs10_req_destroy(botan_x509_pkcs10_req_t req) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(req);
#else
   BOTAN_UNUSED(req);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_pkcs10_req_load_file(botan_x509_pkcs10_req_t* req_obj, const char* req_path) {
   if(Botan::any_null_pointers(req_obj, req_path)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto req = std::make_unique<Botan::PKCS10_Request>(req_path);
      return ffi_new_object(req_obj, std::move(req));
   });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_pkcs10_req_load(botan_x509_pkcs10_req_t* req_obj, const uint8_t req_bits[], size_t req_bits_len) {
   if(Botan::any_null_pointers(req_obj, req_bits)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::DataSource_Memory bits(req_bits, req_bits_len);
      auto req = std::make_unique<Botan::PKCS10_Request>(bits);
      return ffi_new_object(req_obj, std::move(req));
   });
#else
   BOTAN_UNUSED(req_bits_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_pkcs10_req_view_pem(botan_x509_pkcs10_req_t req, botan_view_ctx ctx, botan_view_str_fn view) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(req, [=](const auto& r) -> int { return invoke_view_callback(view, ctx, r.PEM_encode()); });
#else
   BOTAN_UNUSED(req, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_pkcs10_req_view_der(botan_x509_pkcs10_req_t req, botan_view_ctx ctx, botan_view_bin_fn view) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(req, [=](const auto& r) -> int { return invoke_view_callback(view, ctx, r.BER_encode()); });
#else
   BOTAN_UNUSED(req, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_pkcs10_req_get_public_key(botan_x509_pkcs10_req_t req, botan_pubkey_t* key) {
   if(Botan::any_null_pointers(key)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(req,
                          [=](const auto& r) -> int { return ffi_new_object(key, std::move(r.subject_public_key())); });
#else
   BOTAN_UNUSED(req);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_pkcs10_req_verify_signature(botan_x509_pkcs10_req_t req, botan_pubkey_t key) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(req, [=](const auto& r) -> int { return r.check_signature(safe_get(key)) ? 1 : 0; });
#else
   BOTAN_UNUSED(req, key);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_pkcs10_req_sign(botan_x509_cert_t* subject_cert,
                               botan_x509_pkcs10_req_t subject_req,
                               botan_x509_cert_t issuing_cert,
                               botan_privkey_t issuing_key,
                               botan_rng_t rng,
                               uint64_t not_before,
                               uint64_t not_after,
                               const botan_mp_t* serial_number,
                               const char* hash_fn,
                               const char* padding) {
   if(Botan::any_null_pointers(subject_cert)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto& rng_ = safe_get(rng);

      auto ca = Botan::X509_CA(
         safe_get(issuing_cert), safe_get(issuing_key), default_from_ptr(hash_fn), default_from_ptr(padding), rng_);

      std::unique_ptr<Botan::X509_Certificate> cert;
      if(serial_number != nullptr) {
         auto serial = safe_get(*serial_number);
         cert = std::make_unique<Botan::X509_Certificate>(ca.sign_request(
            safe_get(subject_req), rng_, serial, time_from_timestamp(not_before), time_from_timestamp(not_after)));
      } else {
         cert = std::make_unique<Botan::X509_Certificate>(ca.sign_request(
            safe_get(subject_req), rng_, time_from_timestamp(not_before), time_from_timestamp(not_after)));
      }

      return ffi_new_object(subject_cert, std::move(cert));
   });
#else
   BOTAN_UNUSED(subject_req, issuing_cert, issuing_key, rng, not_before, not_after, serial_number, hash_fn, padding);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_load_file(botan_x509_crl_t* crl_obj, const char* crl_path) {
   if(Botan::any_null_pointers(crl_obj, crl_path)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

   return ffi_guard_thunk(__func__, [=]() -> int {
      auto c = std::make_unique<Botan::X509_CRL>(crl_path);
      return ffi_new_object(crl_obj, std::move(c));
   });

#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_load(botan_x509_crl_t* crl_obj, const uint8_t crl_bits[], size_t crl_bits_len) {
   if(Botan::any_null_pointers(crl_obj, crl_bits)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::DataSource_Memory bits(crl_bits, crl_bits_len);
      auto c = std::make_unique<Botan::X509_CRL>(bits);
      return ffi_new_object(crl_obj, std::move(c));
   });
#else
   BOTAN_UNUSED(crl_bits_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_this_update(botan_x509_crl_t crl, uint64_t* time_since_epoch) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(crl, [=](const auto& c) {
      if(Botan::any_null_pointers(time_since_epoch)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }
      *time_since_epoch = c.this_update().time_since_epoch();
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(crl, time_since_epoch);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_next_update(botan_x509_crl_t crl, uint64_t* time_since_epoch) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(crl, [=](const auto& c) {
      const auto& time = c.next_update();
      if(!time.time_is_set()) {
         return BOTAN_FFI_ERROR_NO_VALUE;
      }

      if(Botan::any_null_pointers(time_since_epoch)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      *time_since_epoch = c.next_update().time_since_epoch();
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(crl, time_since_epoch);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_create(botan_x509_crl_t* crl_obj,
                          botan_rng_t rng,
                          botan_x509_cert_t ca_cert,
                          botan_privkey_t ca_key,
                          uint64_t issue_time,
                          uint32_t next_update,
                          const char* hash_fn,
                          const char* padding) {
   if(Botan::any_null_pointers(crl_obj)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto& rng_ = safe_get(rng);
      auto ca = Botan::X509_CA(
         safe_get(ca_cert), safe_get(ca_key), default_from_ptr(hash_fn), default_from_ptr(padding), rng_);
      auto crl = std::make_unique<Botan::X509_CRL>(
         ca.new_crl(rng_, timepoint_from_timestamp(issue_time), std::chrono::seconds(next_update)));
      return ffi_new_object(crl_obj, std::move(crl));
   });
#else
   BOTAN_UNUSED(rng, ca_cert, ca_key, hash_fn, padding, issue_time, next_update);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_entry_create(botan_x509_crl_entry_t* entry, botan_x509_cert_t cert, int reason_code) {
   if(Botan::any_null_pointers(entry)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      return ffi_new_object(
         entry, std::make_unique<Botan::CRL_Entry>(safe_get(cert), static_cast<Botan::CRL_Code>(reason_code)));
   });
#else
   BOTAN_UNUSED(cert, reason_code);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_update(botan_x509_crl_t* crl_obj,
                          botan_x509_crl_t last_crl,
                          botan_rng_t rng,
                          botan_x509_cert_t ca_cert,
                          botan_privkey_t ca_key,
                          uint64_t issue_time,
                          uint32_t next_update,
                          const botan_x509_crl_entry_t* new_entries,
                          size_t new_entries_len,
                          const char* hash_fn,
                          const char* padding) {
   if(Botan::any_null_pointers(crl_obj)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   if(new_entries_len > 0 && Botan::any_null_pointers(new_entries)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto& rng_ = safe_get(rng);
      auto ca = Botan::X509_CA(
         safe_get(ca_cert), safe_get(ca_key), default_from_ptr(hash_fn), default_from_ptr(padding), rng_);

      std::vector<Botan::CRL_Entry> entries;
      entries.reserve(new_entries_len);
      for(size_t i = 0; i < new_entries_len; i++) {
         entries.push_back(safe_get(new_entries[i]));
      }

      auto crl = std::make_unique<Botan::X509_CRL>(ca.update_crl(
         safe_get(last_crl), entries, rng_, timepoint_from_timestamp(issue_time), std::chrono::seconds(next_update)));
      return ffi_new_object(crl_obj, std::move(crl));
   });
#else
   BOTAN_UNUSED(
      last_crl, rng, ca_cert, ca_key, hash_fn, padding, issue_time, next_update, new_entries, new_entries_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_verify_signature(botan_x509_crl_t crl, botan_pubkey_t key) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(crl, [=](const auto& c) -> int { return c.check_signature(safe_get(key)) ? 1 : 0; });
#else
   BOTAN_UNUSED(crl, key);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_destroy(botan_x509_crl_t crl) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(crl);
#else
   BOTAN_UNUSED(crl);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_view_binary_values(botan_x509_crl_t crl_obj,
                                      botan_x509_value_type value_type,
                                      size_t index,
                                      botan_view_ctx ctx,
                                      botan_view_bin_fn view_fn) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   if(index != 0) {
      // As of now there are no multi-value binary entries.
      return BOTAN_FFI_ERROR_OUT_OF_RANGE;
   }

   auto view = [=](std::span<const uint8_t> value) -> int {
      if(value.empty()) {
         return BOTAN_FFI_ERROR_NO_VALUE;
      } else {
         return invoke_view_callback(view_fn, ctx, value);
      }
   };

   return BOTAN_FFI_VISIT(crl_obj, [=](const Botan::X509_CRL& crl) -> int {
      switch(value_type) {
         case BOTAN_X509_SERIAL_NUMBER: {
            if(const auto& crln = crl.crl_number_bigint()) {
               // Previously CRL number was a fixed 4 byte value, continue this for small CRL numbers
               const size_t view_bytes = std::min<size_t>(crln->bytes(), 4);
               return view(crln->serialize<std::vector<uint8_t>>(view_bytes));
            } else {
               return BOTAN_FFI_ERROR_NO_VALUE;
            }
         }
         case BOTAN_X509_ISSUER_DN_BITS:
            return view(Botan::ASN1::put_in_sequence(crl.issuer_dn().get_bits()));
         case BOTAN_X509_AUTHORITY_KEY_IDENTIFIER:
            return view(crl.authority_key_id());

         case BOTAN_X509_TBS_DATA_BITS:
         case BOTAN_X509_SIGNATURE_SCHEME_BITS:
         case BOTAN_X509_SIGNATURE_BITS:
         case BOTAN_X509_DER_ENCODING:
            return botan_x509_object_view_value(crl, value_type, index, ctx, view_fn);

         case BOTAN_X509_SUBJECT_DN_BITS:
         case BOTAN_X509_SUBJECT_KEY_IDENTIFIER:
         case BOTAN_X509_PUBLIC_KEY_PKCS8_BITS:
         case BOTAN_X509_PEM_ENCODING:
         case BOTAN_X509_CRL_DISTRIBUTION_URLS:
         case BOTAN_X509_OCSP_RESPONDER_URLS:
         case BOTAN_X509_CA_ISSUERS_URLS:
            return BOTAN_FFI_ERROR_NO_VALUE;
      }

      return BOTAN_FFI_ERROR_BAD_PARAMETER;
   });
#else
   BOTAN_UNUSED(crl_obj, value_type, index, ctx, view_fn);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_view_binary_values_count(botan_x509_crl_t crl_obj, botan_x509_value_type value_type, size_t* count) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return enumerator_count_values(count, [=](size_t index) {
      return botan_x509_crl_view_binary_values(
         crl_obj, value_type, index, nullptr, [](auto, auto, auto) -> int { return BOTAN_FFI_SUCCESS; });
   });
#else
   BOTAN_UNUSED(crl_obj, value_type, count);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_view_string_values(botan_x509_crl_t crl_obj,
                                      botan_x509_value_type value_type,
                                      size_t index,
                                      botan_view_ctx ctx,
                                      botan_view_str_fn view) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(crl_obj, [=](const Botan::X509_CRL& crl) -> int {
      switch(value_type) {
         case BOTAN_X509_PEM_ENCODING:
            return botan_x509_object_view_value(crl, value_type, index, ctx, view);

         case BOTAN_X509_SERIAL_NUMBER:
         case BOTAN_X509_SUBJECT_DN_BITS:
         case BOTAN_X509_ISSUER_DN_BITS:
         case BOTAN_X509_SUBJECT_KEY_IDENTIFIER:
         case BOTAN_X509_AUTHORITY_KEY_IDENTIFIER:
         case BOTAN_X509_PUBLIC_KEY_PKCS8_BITS:
         case BOTAN_X509_TBS_DATA_BITS:
         case BOTAN_X509_SIGNATURE_SCHEME_BITS:
         case BOTAN_X509_SIGNATURE_BITS:
         case BOTAN_X509_DER_ENCODING:
         case BOTAN_X509_CRL_DISTRIBUTION_URLS:
         case BOTAN_X509_OCSP_RESPONDER_URLS:
         case BOTAN_X509_CA_ISSUERS_URLS:
            return BOTAN_FFI_ERROR_NO_VALUE;
      }

      return BOTAN_FFI_ERROR_BAD_PARAMETER;
   });
#else
   BOTAN_UNUSED(crl_obj, value_type, index, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_view_string_values_count(botan_x509_crl_t crl_obj, botan_x509_value_type value_type, size_t* count) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return enumerator_count_values(count, [=](size_t index) {
      return botan_x509_crl_view_string_values(
         crl_obj, value_type, index, nullptr, [](auto, auto, auto) -> int { return BOTAN_FFI_SUCCESS; });
   });
#else
   BOTAN_UNUSED(crl_obj, value_type, count);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_is_revoked(botan_x509_crl_t crl, botan_x509_cert_t cert) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(crl, [=](const auto& c) { return c.is_revoked(safe_get(cert)) ? 0 : -1; });
#else
   BOTAN_UNUSED(cert);
   BOTAN_UNUSED(crl);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_entries(botan_x509_crl_t crl, size_t index, botan_x509_crl_entry_t* entry) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(crl, [=](const Botan::X509_CRL& c) -> int {
      const auto& entries = c.get_revoked();
      if(index >= entries.size()) {
         return BOTAN_FFI_ERROR_OUT_OF_RANGE;
      }

      if(Botan::any_null_pointers(entry)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      return ffi_new_object(entry, std::make_unique<Botan::CRL_Entry>(entries[index]));
   });
#else
   BOTAN_UNUSED(crl, index, entry);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_entries_count(botan_x509_crl_t crl, size_t* count) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   if(Botan::any_null_pointers(count)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(crl, [=](const Botan::X509_CRL& c) { *count = c.get_revoked().size(); });
#else
   BOTAN_UNUSED(crl, count);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_entry_destroy(botan_x509_crl_entry_t entry) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(entry);
#else
   BOTAN_UNUSED(entry);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_entry_reason(botan_x509_crl_entry_t entry, int* reason_code) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(entry, [=](const Botan::CRL_Entry& e) {
      if(Botan::any_null_pointers(reason_code)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      *reason_code = static_cast<int>(e.reason_code());
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(entry, reason_code);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_entry_serial_number(botan_x509_crl_entry_t entry, botan_mp_t* serial_number) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(entry, [=](const Botan::CRL_Entry& e) {
      if(Botan::any_null_pointers(serial_number)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      auto serial_bn = e.serial().to_bigint();
      return ffi_new_object(serial_number, std::make_unique<Botan::BigInt>(std::move(serial_bn)));
   });
#else
   BOTAN_UNUSED(entry, serial_number);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_entry_view_serial_number(botan_x509_crl_entry_t entry, botan_view_ctx ctx, botan_view_bin_fn view) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(
      entry, [=](const Botan::CRL_Entry& e) { return invoke_view_callback(view, ctx, e.serial_number()); });
#else
   BOTAN_UNUSED(entry, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_entry_revocation_date(botan_x509_crl_entry_t entry, uint64_t* time_since_epoch) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(entry, [=](const Botan::CRL_Entry& e) {
      if(Botan::any_null_pointers(time_since_epoch)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      *time_since_epoch = e.expire_time().time_since_epoch();
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(entry, time_since_epoch);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_verify_with_crl(int* result_code,
                                    botan_x509_cert_t cert,
                                    const botan_x509_cert_t* intermediates,
                                    size_t intermediates_len,
                                    const botan_x509_cert_t* trusted,
                                    size_t trusted_len,
                                    const botan_x509_crl_t* crls,
                                    size_t crls_len,
                                    const char* trusted_path,
                                    size_t required_strength,
                                    const char* hostname_cstr,
                                    uint64_t reference_time) {
   if(required_strength == 0) {
      required_strength = 110;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      const std::string hostname((hostname_cstr == nullptr) ? "" : hostname_cstr);
      const Botan::Usage_Type usage = Botan::Usage_Type::UNSPECIFIED;
      const auto validation_time = reference_time == 0
                                      ? std::chrono::system_clock::now()
                                      : std::chrono::system_clock::from_time_t(static_cast<time_t>(reference_time));

      if(intermediates_len > 0 && intermediates == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }
      if(trusted_len > 0 && trusted == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }
      if(crls_len > 0 && crls == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      std::vector<Botan::X509_Certificate> end_certs;
      end_certs.push_back(safe_get(cert));
      for(size_t i = 0; i != intermediates_len; ++i) {
         end_certs.push_back(safe_get(intermediates[i]));
      }

      std::unique_ptr<Botan::Certificate_Store> trusted_from_path;
      std::unique_ptr<Botan::Certificate_Store_In_Memory> trusted_extra;
      std::unique_ptr<Botan::Certificate_Store_In_Memory> trusted_crls;
      std::vector<Botan::Certificate_Store*> trusted_roots;

      if(trusted_path != nullptr && *trusted_path != 0) {
         trusted_from_path = std::make_unique<Botan::Certificate_Store_In_Memory>(trusted_path);
         trusted_roots.push_back(trusted_from_path.get());
      }

      if(trusted_len > 0) {
         trusted_extra = std::make_unique<Botan::Certificate_Store_In_Memory>();
         for(size_t i = 0; i != trusted_len; ++i) {
            trusted_extra->add_certificate(safe_get(trusted[i]));
         }
         trusted_roots.push_back(trusted_extra.get());
      }

      if(crls_len > 0) {
         trusted_crls = std::make_unique<Botan::Certificate_Store_In_Memory>();
         for(size_t i = 0; i != crls_len; ++i) {
            trusted_crls->add_crl(safe_get(crls[i]));
         }
         trusted_roots.push_back(trusted_crls.get());
      }

      const Botan::Path_Validation_Restrictions restrictions(false, required_strength);

      auto validation_result =
         Botan::x509_path_validate(end_certs, restrictions, trusted_roots, hostname, usage, validation_time);

      if(result_code != nullptr) {
         *result_code = static_cast<int>(validation_result.result());
      }

      if(validation_result.successful_validation()) {
         return 0;
      } else {
         return 1;
      }
   });
#else
   BOTAN_UNUSED(result_code, cert, intermediates, intermediates_len, trusted);
   BOTAN_UNUSED(trusted_len, trusted_path, hostname_cstr, reference_time, crls, crls_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}
}
