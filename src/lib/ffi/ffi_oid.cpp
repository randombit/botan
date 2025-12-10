/*
* (C) 2025 Jack Lloyd
* (C) 2025 Dominik Schricker
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>

#include <botan/pk_keys.h>
#include <botan/internal/ffi_oid.h>
#include <botan/internal/ffi_pkey.h>
#include <botan/internal/ffi_util.h>

extern "C" {

using namespace Botan_FFI;

int botan_oid_destroy(botan_asn1_oid_t oid) {
   return BOTAN_FFI_CHECKED_DELETE(oid);
}

int botan_oid_from_string(botan_asn1_oid_t* oid_obj, const char* oid_str) {
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(oid_obj == nullptr || oid_str == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }
      Botan::OID oid;
      // This returns a Lookup_Error if an unknown name is passed,
      // which would get turned into NOT_IMPLEMENTED
      try {
         oid = Botan::OID::from_string(oid_str);
      } catch(Botan::Lookup_Error&) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
      auto oid_ptr = std::make_unique<Botan::OID>(std::move(oid));
      return ffi_new_object(oid_obj, std::move(oid_ptr));
   });
}

int botan_oid_register(botan_asn1_oid_t oid, const char* name) {
   return BOTAN_FFI_VISIT(oid, [=](const auto& o) -> int {
      if(name == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }
      Botan::OID::register_oid(o, name);
      return BOTAN_FFI_SUCCESS;
   });
}

int botan_oid_view_string(botan_asn1_oid_t oid, botan_view_ctx ctx, botan_view_str_fn view) {
   return BOTAN_FFI_VISIT(oid, [=](const auto& o) -> int { return invoke_view_callback(view, ctx, o.to_string()); });
}

int botan_oid_view_name(botan_asn1_oid_t oid, botan_view_ctx ctx, botan_view_str_fn view) {
   return BOTAN_FFI_VISIT(
      oid, [=](const auto& o) -> int { return invoke_view_callback(view, ctx, o.to_formatted_string()); });
}

int botan_oid_equal(botan_asn1_oid_t a_w, botan_asn1_oid_t b_w) {
   return BOTAN_FFI_VISIT(a_w, [=](const auto& a) -> int { return a == safe_get(b_w); });
}

int botan_oid_cmp(int* result, botan_asn1_oid_t a_w, botan_asn1_oid_t b_w) {
   return BOTAN_FFI_VISIT(a_w, [=](auto& a) {
      if(result == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }
      const Botan::OID b = safe_get(b_w);
      // we don't have .cmp for OID
      if(a == b) {
         *result = 0;
      } else if(a < b) {
         *result = -1;
      } else {
         *result = 1;
      }
      return BOTAN_FFI_SUCCESS;
   });
}
}
