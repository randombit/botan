/*
* (C) 2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/internal/ffi_util.h>
#include <botan/internal/ffi_pkey.h>

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   #include <botan/x509cert.h>
   #include <botan/data_src.h>
#endif

extern "C" {

using namespace Botan_FFI;

#if defined(BOTAN_HAS_X509_CERTIFICATES)

BOTAN_FFI_DECLARE_STRUCT(botan_x509_cert_struct, Botan::X509_Certificate, 0x8F628937);

#endif

int botan_x509_cert_load_file(botan_x509_cert_t* cert_obj, const char* cert_path)
   {
   if(!cert_obj || !cert_path)
      return BOTAN_FFI_ERROR_NULL_POINTER;

#if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

   return ffi_guard_thunk(BOTAN_CURRENT_FUNCTION, [=]() -> int {
      std::unique_ptr<Botan::X509_Certificate> c(new Botan::X509_Certificate(cert_path));
      *cert_obj = new botan_x509_cert_struct(c.release());
      return BOTAN_FFI_SUCCESS;
      });

#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_x509_cert_load(botan_x509_cert_t* cert_obj, const uint8_t cert_bits[], size_t cert_bits_len)
   {
   if(!cert_obj || !cert_bits)
      return BOTAN_FFI_ERROR_NULL_POINTER;

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(BOTAN_CURRENT_FUNCTION, [=]() -> int {
      Botan::DataSource_Memory bits(cert_bits, cert_bits_len);
      std::unique_ptr<Botan::X509_Certificate> c(new Botan::X509_Certificate(bits));
      *cert_obj = new botan_x509_cert_struct(c.release());
      return BOTAN_FFI_SUCCESS;
      });
#else
   BOTAN_UNUSED(cert_bits_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_x509_cert_get_public_key(botan_x509_cert_t cert, botan_pubkey_t* key)
   {
   if(key == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;

   *key = nullptr;

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(BOTAN_CURRENT_FUNCTION, [=]() -> int {
      std::unique_ptr<Botan::Public_Key> publicKey = safe_get(cert).load_subject_public_key();
      *key = new botan_pubkey_struct(publicKey.release());
      return BOTAN_FFI_SUCCESS;
      });
#else
   BOTAN_UNUSED(cert, key);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_x509_cert_get_issuer_dn(botan_x509_cert_t cert,
                                  const char* key, size_t index,
                                  uint8_t out[], size_t* out_len)
   {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_DO(Botan::X509_Certificate, cert, c, { return write_str_output(out, out_len, c.issuer_info(key).at(index)); });
#else
   BOTAN_UNUSED(cert, key, index, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_x509_cert_get_subject_dn(botan_x509_cert_t cert,
                                   const char* key, size_t index,
                                   uint8_t out[], size_t* out_len)
   {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_DO(Botan::X509_Certificate, cert, c, { return write_str_output(out, out_len, c.subject_info(key).at(index)); });
#else
   BOTAN_UNUSED(cert, key, index, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_x509_cert_to_string(botan_x509_cert_t cert, char out[], size_t* out_len)
   {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_DO(Botan::X509_Certificate, cert, c, { return write_str_output(out, out_len, c.to_string()); });
#else
   BOTAN_UNUSED(cert, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_x509_cert_allowed_usage(botan_x509_cert_t cert, unsigned int key_usage)
   {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_DO(Botan::X509_Certificate, cert, c, {
      const Botan::Key_Constraints k = static_cast<Botan::Key_Constraints>(key_usage);
      if(c.allowed_usage(k))
         return BOTAN_FFI_SUCCESS;
      return 1;
      });
#else
   BOTAN_UNUSED(cert, key_usage);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_x509_cert_destroy(botan_x509_cert_t cert)
   {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(cert);
#else
   BOTAN_UNUSED(cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_x509_cert_get_time_starts(botan_x509_cert_t cert, char out[], size_t* out_len)
   {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_DO(Botan::X509_Certificate, cert, c, { return write_str_output(out, out_len, c.not_before().to_string()); });
#else
   BOTAN_UNUSED(cert, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_x509_cert_get_time_expires(botan_x509_cert_t cert, char out[], size_t* out_len)
   {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_DO(Botan::X509_Certificate, cert, c, { return write_str_output(out, out_len, c.not_after().to_string()); });
#else
   BOTAN_UNUSED(cert, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_x509_cert_get_serial_number(botan_x509_cert_t cert, uint8_t out[], size_t* out_len)
   {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_DO(Botan::X509_Certificate, cert, c, { return write_vec_output(out, out_len, c.serial_number()); });
#else
   BOTAN_UNUSED(cert, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_x509_cert_get_fingerprint(botan_x509_cert_t cert, const char* hash, uint8_t out[], size_t* out_len)
   {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_DO(Botan::X509_Certificate, cert, c, { return write_str_output(out, out_len, c.fingerprint(hash)); });
#else
   BOTAN_UNUSED(cert, hash, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_x509_cert_get_authority_key_id(botan_x509_cert_t cert, uint8_t out[], size_t* out_len)
   {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_DO(Botan::X509_Certificate, cert, c, { return write_vec_output(out, out_len, c.authority_key_id()); });
#else
   BOTAN_UNUSED(cert, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_x509_cert_get_subject_key_id(botan_x509_cert_t cert, uint8_t out[], size_t* out_len)
   {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_DO(Botan::X509_Certificate, cert, c, { return write_vec_output(out, out_len, c.subject_key_id()); });
#else
   BOTAN_UNUSED(cert, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_x509_cert_get_public_key_bits(botan_x509_cert_t cert, uint8_t out[], size_t* out_len)
   {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_DO(Botan::X509_Certificate, cert, c, { return write_vec_output(out, out_len, c.subject_public_key_bits()); });
#else
   BOTAN_UNUSED(cert, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_x509_cert_hostname_match(botan_x509_cert_t cert, const char* hostname)
   {
   if(hostname == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_DO(Botan::X509_Certificate, cert, c,
                       { return c.matches_dns_name(hostname) ? 0 : -1; });
#else
   BOTAN_UNUSED(cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

}
