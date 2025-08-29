/*
* (C) 2015,2017,2018 Jack Lloyd
* (C) 2025 Dominik Schricker
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>

#include <botan/internal/ffi_cert.h>
#include <botan/internal/ffi_cert_ext.h>
#include <botan/internal/ffi_mp.h>
#include <botan/internal/ffi_oid.h>
#include <botan/internal/ffi_pkey.h>
#include <botan/internal/ffi_rng.h>
#include <botan/internal/ffi_util.h>
#include <memory>

namespace {
std::chrono::system_clock::time_point timepoint_from_timestamp(uint64_t time_since_epoch) {
   return std::chrono::system_clock::time_point(std::chrono::seconds(time_since_epoch));
}

Botan::X509_Time time_from_timestamp(uint64_t time_since_epoch) {
   return Botan::X509_Time(timepoint_from_timestamp(time_since_epoch));
}

template <typename T, typename U>
T default_from_ptr(U* value) {
   T ret;
   if(value != nullptr) {
      ret = value;
   }
   return ret;
}

template <typename T>
std::optional<T> optional_from_ptr(T* value) {
   if(value != nullptr) {
      return *value;
   }
   return std::nullopt;
}

std::optional<std::string> optional_from_ptr(const char* value) {
   if(value != nullptr) {
      return std::string(value);
   }
   return std::nullopt;
}
}  // namespace

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

int botan_x509_cert_get_issuer_dn_count(botan_x509_cert_t cert, const char* key, size_t* len) {
   if(key == nullptr || len == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) -> int {
      auto issuer_info = c.issuer_info(key);
      *len = issuer_info.size();
      return BOTAN_FFI_SUCCESS;
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
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });
#else
   BOTAN_UNUSED(cert, key, index, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_subject_dn_count(botan_x509_cert_t cert, const char* key, size_t* len) {
   if(key == nullptr || len == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) -> int {
      auto issuer_info = c.subject_info(key);
      *len = issuer_info.size();
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(cert);
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
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });
#else
   BOTAN_UNUSED(cert, key, index, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_subject_name(botan_x509_cert_t cert, botan_view_ctx ctx, botan_view_str_fn view) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert,
                          [=](const auto& c) { return invoke_view_callback(view, ctx, c.subject_dn().to_string()); });
#else
   BOTAN_UNUSED(cert, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_issuer_name(botan_x509_cert_t cert, botan_view_ctx ctx, botan_view_str_fn view) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert,
                          [=](const auto& c) { return invoke_view_callback(view, ctx, c.subject_dn().to_string()); });
#else
   BOTAN_UNUSED(cert, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_to_string(botan_x509_cert_t cert, char out[], size_t* out_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return copy_view_str(reinterpret_cast<uint8_t*>(out), out_len, botan_x509_cert_view_as_string, cert);
#else
   BOTAN_UNUSED(cert, out, out_len)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_view_as_string(botan_x509_cert_t cert, botan_view_ctx ctx, botan_view_str_fn view) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { return invoke_view_callback(view, ctx, c.to_string()); });
#else
   BOTAN_UNUSED(cert, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_view_pem(botan_x509_cert_t cert, botan_view_ctx ctx, botan_view_str_fn view) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { return invoke_view_callback(view, ctx, c.PEM_encode()); });
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

int botan_x509_cert_get_allowed_usage(botan_x509_cert_t cert, uint32_t* usage) {
   if(usage == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) -> int {
      *usage = c.constraints().value();
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(cert)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_is_ca(botan_x509_cert_t cert, int* is_ca, size_t* limit) {
   if(is_ca == nullptr || limit == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) -> int {
      if(c.is_CA_cert()) {
         *is_ca = 1;
         *limit = c.path_limit();
      } else {
         *is_ca = 0;
         *limit = 0;
      }
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(cert)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_ocsp_responder(botan_x509_cert_t cert, botan_view_ctx ctx, botan_view_str_fn view) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert,
                          [=](const auto& c) -> int { return invoke_view_callback(view, ctx, c.ocsp_responder()); });
#else
   BOTAN_UNUSED(cert, ctx, view)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_is_self_signed(botan_x509_cert_t cert, int* out) {
   if(out == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) {
      if(c.is_self_signed()) {
         *out = 1;
      } else {
         *out = 0;
      }
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(cert, out)
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

      Botan::Path_Validation_Restrictions restrictions(false, required_strength);

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
   Botan::Certificate_Status_Code sc = static_cast<Botan::Certificate_Status_Code>(code);
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

int botan_x509_crl_create(botan_x509_crl_t* crl_obj,
                          botan_rng_t rng,
                          botan_x509_cert_t ca_cert,
                          botan_privkey_t ca_key,
                          uint64_t issue_time,
                          uint32_t next_update,
                          const char* hash_fn,
                          const char* padding) {
   if(crl_obj == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto& rng_ = safe_get(rng);
      auto ca = Botan::X509_CA(safe_get(ca_cert),
                               safe_get(ca_key),
                               default_from_ptr<std::string>(hash_fn),
                               default_from_ptr<std::string>(padding),
                               rng_);
      auto crl = std::make_unique<Botan::X509_CRL>(
         ca.new_crl(rng_, timepoint_from_timestamp(issue_time), std::chrono::seconds(next_update)));
      return ffi_new_object(crl_obj, std::move(crl));
   });
#else
   BOTAN_UNUSED(rng, ca_cert, ca_key, hash_fn, padding, issue_time, next_update);
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
                          const botan_x509_cert_t* revoked,
                          size_t revoked_len,
                          uint8_t reason,
                          const char* hash_fn,
                          const char* padding) {
   if(crl_obj == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(revoked_len == 0) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
      auto& rng_ = safe_get(rng);
      auto ca = Botan::X509_CA(safe_get(ca_cert),
                               safe_get(ca_key),
                               default_from_ptr<std::string>(hash_fn),
                               default_from_ptr<std::string>(padding),
                               rng_);

      std::vector<Botan::CRL_Entry> entries;
      for(size_t i = 0; i < revoked_len; i++) {
         entries.push_back(Botan::CRL_Entry(safe_get(revoked[i]), static_cast<Botan::CRL_Code>(reason)));
      }

      auto crl = std::make_unique<Botan::X509_CRL>(ca.update_crl(
         safe_get(last_crl), entries, rng_, timepoint_from_timestamp(issue_time), std::chrono::seconds(next_update)));
      return ffi_new_object(crl_obj, std::move(crl));
   });
#else
   BOTAN_UNUSED(
      last_crl, rng, ca_cert, ca_key, hash_fn, padding, issue_time, next_update, revoked, revoked_len, reason);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_get_count(botan_x509_crl_t crl, size_t* count) {
   if(count == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(crl, [=](const auto& c) {
      *count = c.get_revoked().size();
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(crl);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_get_entry(
   botan_x509_crl_t crl, size_t i, botan_mp_t serial, uint64_t* expire_time, uint8_t* reason) {
   if(expire_time == nullptr || reason == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   const auto& entries = safe_get(crl).get_revoked();
   if(i >= entries.size()) {
      return BOTAN_FFI_ERROR_BAD_PARAMETER;
   }
   *reason = static_cast<uint8_t>(entries[i].reason_code());
   *expire_time = entries[i].expire_time().time_since_epoch();
   safe_get(serial)._assign_from_bytes(entries[i].serial_number());
   return BOTAN_FFI_SUCCESS;
#else
   BOTAN_UNUSED(crl, i, serial);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_verify_signature(botan_x509_crl_t crl, botan_pubkey_t key, int* result) {
   if(result == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      bool ok = safe_get(crl).check_signature(safe_get(key));
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

int botan_x509_crl_view_pem(botan_x509_crl_t crl, botan_view_ctx ctx, botan_view_str_fn view) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(crl, [=](const auto& c) -> int { return invoke_view_callback(view, ctx, c.PEM_encode()); });
#else
   BOTAN_UNUSED(crl, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_view_der(botan_x509_crl_t crl, botan_view_ctx ctx, botan_view_bin_fn view) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(crl, [=](const auto& c) -> int { return invoke_view_callback(view, ctx, c.BER_encode()); });
#else
   BOTAN_UNUSED(crl, ctx, view);
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

      Botan::Path_Validation_Restrictions restrictions(false, required_strength);

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

int botan_x509_cert_params_builder_destroy(botan_x509_cert_params_builder_t builder) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(builder);
#else
   BOTAN_UNUSED(builder);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_params_builder_create(botan_x509_cert_params_builder_t* builder_obj) {
   if(builder_obj == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto co = std::make_unique<Botan::CertificateParametersBuilder>();
      return ffi_new_object(builder_obj, std::move(co));
   });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   // NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
   #define X509_GET_CERT_PARAMS_BUILDER_STRING(FIELD_NAME)                                          \
      int botan_x509_cert_params_builder_add_##FIELD_NAME(botan_x509_cert_params_builder_t builder, \
                                                          const char* value) {                      \
         if(value == nullptr) {                                                                     \
            return BOTAN_FFI_ERROR_NULL_POINTER;                                                    \
         }                                                                                          \
         return BOTAN_FFI_VISIT(builder, [=](auto& o) { o.add_##FIELD_NAME(value); });              \
      }
#else
   // NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
   #define X509_GET_CERT_PARAMS_BUILDER_STRING(FIELD_NAME)                                          \
      int botan_x509_cert_params_builder_add_##FIELD_NAME(botan_x509_cert_params_builder_t builder, \
                                                          const char* value) {                      \
         if(value == nullptr) {                                                                     \
            return BOTAN_FFI_ERROR_NULL_POINTER;                                                    \
         }                                                                                          \
         BOTAN_UNUSED(builder);                                                                     \
         return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;                                                    \
      }
#endif

X509_GET_CERT_PARAMS_BUILDER_STRING(common_name)
X509_GET_CERT_PARAMS_BUILDER_STRING(country)
X509_GET_CERT_PARAMS_BUILDER_STRING(state)
X509_GET_CERT_PARAMS_BUILDER_STRING(locality)
X509_GET_CERT_PARAMS_BUILDER_STRING(serial_number)
X509_GET_CERT_PARAMS_BUILDER_STRING(organization)
X509_GET_CERT_PARAMS_BUILDER_STRING(organizational_unit)
X509_GET_CERT_PARAMS_BUILDER_STRING(email)
X509_GET_CERT_PARAMS_BUILDER_STRING(dns)
X509_GET_CERT_PARAMS_BUILDER_STRING(uri)
X509_GET_CERT_PARAMS_BUILDER_STRING(xmpp)

int botan_x509_cert_params_builder_add_ipv4(botan_x509_cert_params_builder_t builder, uint32_t ipv4) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(builder, [=](auto& o) { o.add_ipv4(ipv4); });
#else
   BOTAN_UNUSED(builder, ipv4);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_params_builder_add_allowed_usage(botan_x509_cert_params_builder_t builder, uint32_t usage) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(builder, [=](auto& o) { o.add_allowed_usage(Botan::Key_Constraints(usage)); });
#else
   BOTAN_UNUSED(builder, usage);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_params_builder_add_allowed_extended_usage(botan_x509_cert_params_builder_t builder,
                                                              botan_asn1_oid_t oid) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      safe_get(builder).add_allowed_extended_usage(safe_get(oid));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(builder, oid);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_params_builder_set_as_ca_certificate(botan_x509_cert_params_builder_t builder, size_t* limit) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(builder, [=](auto& o) {
      auto limit_ = optional_from_ptr<size_t>(limit);
      o.set_as_ca_certificate(limit_);
   });
#else
   BOTAN_UNUSED(builder, limit);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_params_builder_add_ext_ip_addr_blocks(botan_x509_cert_params_builder_t builder,
                                                          botan_x509_ext_ip_addr_blocks_t ip_addr_blocks,
                                                          int is_critical) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(is_critical != 0 && is_critical != 1) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
      try {
         safe_get(builder).add_extension(safe_get(ip_addr_blocks).copy(), static_cast<bool>(is_critical));
      } catch(Botan::Invalid_Argument&) {
         return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE;
      }
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(builder, ip_addr_blocks, is_critical);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_params_builder_add_ext_as_blocks(botan_x509_cert_params_builder_t builder,
                                                     botan_x509_ext_as_blocks_t as_blocks,
                                                     int is_critical) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(is_critical != 0 && is_critical != 1) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
      try {
         safe_get(builder).add_extension(safe_get(as_blocks).copy(), static_cast<bool>(is_critical));
      } catch(Botan::Invalid_Argument&) {
         return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE;
      }
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(builder, as_blocks, is_critical);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_params_builder_into_self_signed(botan_x509_cert_t* cert_obj,
                                                    botan_privkey_t key,
                                                    botan_x509_cert_params_builder_t builder,
                                                    botan_rng_t rng,
                                                    uint64_t not_before,
                                                    uint64_t not_after,
                                                    const botan_mp_t* serial_number,
                                                    const char* hash_fn,
                                                    const char* padding) {
   if(cert_obj == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto hash_fn_ = optional_from_ptr(hash_fn);
      auto padding_ = optional_from_ptr(padding);

      std::unique_ptr<Botan::X509_Certificate> cert;
      if(serial_number != nullptr && false) {
         // TODO
         auto serial_no = safe_get(*serial_number);
      } else {
         cert = std::make_unique<Botan::X509_Certificate>(
            safe_get(builder).into_self_signed_cert(timepoint_from_timestamp(not_before),
                                                    timepoint_from_timestamp(not_after),
                                                    safe_get(key),
                                                    safe_get(rng),
                                                    hash_fn_,
                                                    padding_));
      }

      return ffi_new_object(cert_obj, std::move(cert));
   });
#else
   BOTAN_UNUSED(key, builder, rng, not_before, not_after, hash_fn, padding);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_params_builder_into_pkcs10_req(botan_x509_pkcs10_req_t* req_obj,
                                                   botan_privkey_t key,
                                                   botan_x509_cert_params_builder_t builder,
                                                   botan_rng_t rng,
                                                   const char* hash_fn,
                                                   const char* padding,
                                                   const char* challenge_password) {
   if(req_obj == nullptr) {
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
   BOTAN_UNUSED(key, builder, rng, padding, hash_fn, challenge_password);
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
   if(req_obj == nullptr || req_path == nullptr) {
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
   if(req_obj == nullptr || req_bits == nullptr) {
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
   BOTAN_UNUSED(crl, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_pkcs10_req_get_public_key(botan_x509_pkcs10_req_t req, botan_pubkey_t* key) {
   if(key == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto public_key = safe_get(req).subject_public_key();
      return ffi_new_object(key, std::move(public_key));
   });
#else
   BOTAN_UNUSED(req);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_pkcs10_req_get_allowed_usage(botan_x509_pkcs10_req_t req, uint32_t* usage) {
   if(usage == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(req, [=](const auto& r) -> int {
      *usage = r.constraints().value();
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(cert)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_pkcs10_req_is_ca(botan_x509_pkcs10_req_t req, int* is_ca, size_t* limit) {
   if(is_ca == nullptr || limit == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(req, [=](const auto& r) -> int {
      if(r.is_CA()) {
         *is_ca = 1;
         // TODO
         if(r.path_length_constraint().has_value()) {
            *limit = r.path_length_constraint().value();
         } else {
            *limit = 32;
         }
      } else {
         *is_ca = 0;
         *limit = 0;
      }
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(cert)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_pkcs10_req_verify_signature(botan_x509_pkcs10_req_t req, botan_pubkey_t key, int* result) {
   if(result == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      bool ok = safe_get(req).check_signature(safe_get(key));
      if(ok) {
         *result = 1;
      } else {
         *result = 0;
      }
      return BOTAN_FFI_SUCCESS;
   });
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
   if(subject_cert == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto& rng_ = safe_get(rng);

      auto ca = Botan::X509_CA(safe_get(issuing_cert),
                               safe_get(issuing_key),
                               default_from_ptr<std::string>(hash_fn),
                               default_from_ptr<std::string>(padding),
                               rng_);

      std::unique_ptr<Botan::X509_Certificate> cert;
      if(serial_number != nullptr) {
         auto serial_no = safe_get(*serial_number);
         cert = std::make_unique<Botan::X509_Certificate>(ca.sign_request(
            safe_get(subject_req), rng_, serial_no, time_from_timestamp(not_before), time_from_timestamp(not_after)));
      } else {
         cert = std::make_unique<Botan::X509_Certificate>(ca.sign_request(
            safe_get(subject_req), rng_, time_from_timestamp(not_before), time_from_timestamp(not_after)));
      }

      return ffi_new_object(subject_cert, std::move(cert));
   });
#else
   BOTAN_UNUSED(subject_req, issuing_cert, issuing_key, rng, not_before, not_after, hash_fn, padding);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}
}
