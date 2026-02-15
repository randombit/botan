/*
* (C) 2015,2017,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>

#include <botan/internal/ffi_cert.h>
#include <botan/internal/ffi_pkey.h>
#include <botan/internal/ffi_rng.h>
#include <botan/internal/ffi_util.h>
#include <memory>

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   #include <botan/assert.h>
   #include <botan/data_src.h>
   #include <botan/x509_crl.h>
   #include <botan/x509cert.h>
   #include <botan/x509path.h>
   #include <botan/internal/ffi_mp.h>
   #include <botan/internal/ffi_oid.h>
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
   if(index < altnames.email().size()) {
      auto itr = altnames.email().begin();
      std::advance(itr, index);
      return Botan::GeneralName::email(*itr);
   }
   index -= altnames.email().size();

   if(index < altnames.dns().size()) {
      auto itr = altnames.dns().begin();
      std::advance(itr, index);
      return Botan::GeneralName::dns(*itr);
   }
   index -= altnames.dns().size();

   if(index < altnames.directory_names().size()) {
      auto itr = altnames.directory_names().begin();
      std::advance(itr, index);
      return Botan::GeneralName::directory_name(*itr);
   }
   index -= altnames.directory_names().size();

   if(index < altnames.uris().size()) {
      auto itr = altnames.uris().begin();
      std::advance(itr, index);
      return Botan::GeneralName::uri(*itr);
   }
   index -= altnames.uris().size();

   if(index < altnames.ipv4_address().size()) {
      auto itr = altnames.ipv4_address().begin();
      std::advance(itr, index);
      return Botan::GeneralName::ipv4_address(*itr);
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
   return alt_names.email().size() + alt_names.dns().size() + alt_names.directory_names().size() +
          alt_names.uris().size() + alt_names.ipv4_address().size();
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
         return BOTAN_X509_IP_ADDRESS;
      case Type::Other:
         return BOTAN_X509_OTHER_NAME;
   }

   BOTAN_ASSERT_UNREACHABLE();
}

std::chrono::system_clock::time_point timepoint_from_timestamp(uint64_t time_since_epoch) {
   return std::chrono::system_clock::time_point(std::chrono::seconds(time_since_epoch));
}

std::string default_from_ptr(const char* value) {
   std::string ret;
   if(value != nullptr) {
      ret = value;
   }
   return ret;
}

}  // namespace

}  // namespace Botan_FFI

#endif

extern "C" {

using namespace Botan_FFI;

int botan_x509_cert_load_file(botan_x509_cert_t* cert_obj, const char* cert_path) {
   if(cert_obj == nullptr || cert_path == nullptr) {
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
   if(cert_obj == nullptr || cert_bits == nullptr) {
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
      if(Botan::any_null_pointers(count)) {
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
      if(Botan::any_null_pointers(count)) {
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

      return c.has_ex_constraint(oid) ? BOTAN_FFI_SUCCESS : 1;
   });
#else
   BOTAN_UNUSED(cert, oid);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_allowed_extended_usage_oid(botan_x509_cert_t cert, botan_asn1_oid_t oid) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(
      cert, [=](const auto& c) -> int { return c.has_ex_constraint(safe_get(oid)) ? BOTAN_FFI_SUCCESS : 1; });
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
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { *time_since_epoch = c.not_before().time_since_epoch(); });
#else
   BOTAN_UNUSED(cert, time_since_epoch);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_not_after(botan_x509_cert_t cert, uint64_t* time_since_epoch) {
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

      auto serial_bn = Botan::BigInt::from_bytes(c.serial_number());
      return ffi_new_object(serial_number, std::make_unique<Botan::BigInt>(std::move(serial_bn)));
   });
#else
   BOTAN_UNUSED(cert, serial_number);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_fingerprint(botan_x509_cert_t cert, const char* hash, uint8_t out[], size_t* out_len) {
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

int botan_x509_crl_load_file(botan_x509_crl_t* crl_obj, const char* crl_path) {
   if(crl_obj == nullptr || crl_path == nullptr) {
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
   if(crl_obj == nullptr || crl_bits == nullptr) {
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

int botan_x509_crl_verify_signature(botan_x509_crl_t crl, botan_pubkey_t key, int* result) {
   if(Botan::any_null_pointers(result)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      const bool ok = safe_get(crl).check_signature(safe_get(key));
      if(ok) {
         *result = 1;
      } else {
         *result = 0;
      }
      return BOTAN_FFI_SUCCESS;
   });
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

      auto serial_bn = Botan::BigInt::from_bytes(e.serial_number());
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
