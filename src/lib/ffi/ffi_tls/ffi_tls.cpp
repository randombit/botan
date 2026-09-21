/*
* (C) 2026 Moritz Schmitt
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi_tls.h>

#include <botan/tls_policy.h>
#include <botan/internal/ffi_util.h>
#include <memory>
#include <string>
#include <string_view>

extern "C" {

using namespace Botan_FFI;

// TLS::Client and TLS::Server take their policy as a std::shared_ptr, so the
// handle holds one.
BOTAN_FFI_DECLARE_SHARED_STRUCT(botan_tls_policy_struct, const Botan::TLS::Policy, 0x19781017);

int botan_tls_policy_init(botan_tls_policy_t* policy, const char* name) {
   if(any_null_pointers(policy)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   *policy = nullptr;

   return ffi_guard_thunk(__func__, [=]() -> int {
      const std::string policy_name(name != nullptr ? name : "default");

      if(policy_name == "default") {
         return ffi_new_object(policy, std::make_shared<Botan::TLS::Policy>());
      } else if(policy_name == "strict") {
         return ffi_new_object(policy, std::make_shared<Botan::TLS::Strict_Policy>());
      } else if(policy_name == "bsi_tr_02102_2") {
         return ffi_new_object(policy, std::make_shared<Botan::TLS::BSI_TR_02102_2>());
      }

      return BOTAN_FFI_ERROR_BAD_PARAMETER;
   });
}

int botan_tls_policy_init_from_text(botan_tls_policy_t* policy, const char* text) {
   if(any_null_pointers(policy, text)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   *policy = nullptr;

   return ffi_guard_thunk(__func__, [=]() -> int {
      return ffi_new_object(policy, std::make_shared<Botan::TLS::Text_Policy>(std::string_view(text)));
   });
}

int botan_tls_policy_view_text(botan_tls_policy_t policy, botan_view_ctx ctx, botan_view_str_fn view) {
   return BOTAN_FFI_VISIT(policy, [=](const auto& p) { return invoke_view_callback(view, ctx, p->to_string()); });
}

int botan_tls_policy_destroy(botan_tls_policy_t policy) {
   return BOTAN_FFI_CHECKED_DELETE(policy);
}

}  // extern "C"
