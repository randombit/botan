/*
* (C) 2015,2017,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>

#include <botan/internal/ffi_cert.h>
#include <botan/internal/ffi_mp.h>
#include <botan/internal/ffi_pkey.h>
#include <botan/internal/ffi_rng.h>
#include <botan/internal/ffi_util.h>
#include <memory>

namespace {
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
      auto ca = Botan::X509_CA(
         safe_get(ca_cert), safe_get(ca_key), default_from_ptr(hash_fn), default_from_ptr(padding), rng_);

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
