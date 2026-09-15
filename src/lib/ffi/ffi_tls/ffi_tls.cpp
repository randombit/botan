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
// handle holds one. BOTAN_FFI_DECLARE_STRUCT wraps a unique_ptr, hence the
// intermediate struct (as in ffi_tpm2.cpp).
struct botan_tls_policy_wrapper {
      std::shared_ptr<const Botan::TLS::Policy> policy;
};

BOTAN_FFI_DECLARE_STRUCT(botan_tls_policy_struct, botan_tls_policy_wrapper, 0x19781017);

}  // extern "C"

namespace {

int new_policy_object(botan_tls_policy_t* policy, std::shared_ptr<const Botan::TLS::Policy> obj) {
   auto wrapper = std::make_unique<botan_tls_policy_wrapper>();
   wrapper->policy = std::move(obj);
   return ffi_new_object(policy, std::move(wrapper));
}

}  // namespace

extern "C" {

int botan_tls_policy_init(botan_tls_policy_t* policy, const char* name) {
   if(policy == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   *policy = nullptr;

   return ffi_guard_thunk(__func__, [=]() -> int {
      const std::string policy_name(name != nullptr ? name : "default");

      if(policy_name == "default") {
         return new_policy_object(policy, std::make_shared<Botan::TLS::Policy>());
      } else if(policy_name == "strict") {
         return new_policy_object(policy, std::make_shared<Botan::TLS::Strict_Policy>());
      } else if(policy_name == "bsi_tr_02102_2") {
         return new_policy_object(policy, std::make_shared<Botan::TLS::BSI_TR_02102_2>());
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
      return new_policy_object(policy, std::make_shared<Botan::TLS::Text_Policy>(std::string_view(text)));
   });
}

int botan_tls_policy_view_text(botan_tls_policy_t policy, botan_view_ctx ctx, botan_view_str_fn view) {
   return BOTAN_FFI_VISIT(policy,
                          [=](const auto& p) { return invoke_view_callback(view, ctx, p.policy->to_string()); });
}

int botan_tls_policy_destroy(botan_tls_policy_t policy) {
   return BOTAN_FFI_CHECKED_DELETE(policy);
}

}  // extern "C"
