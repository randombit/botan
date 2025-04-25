/*
* (C) 2025 Jack Lloyd
* (C) 2025 Dominik Schricker
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>

#include <botan/internal/ffi_ec.h>
#include <botan/internal/ffi_mp.h>
#include <botan/internal/ffi_oid.h>
#include <botan/internal/ffi_util.h>
#include <functional>

extern "C" {

using namespace Botan_FFI;

int botan_ec_group_destroy(botan_ec_group_t ec_group) {
   return BOTAN_FFI_CHECKED_DELETE(ec_group);
}

int botan_ec_group_supports_application_specific_group(int* out) {
   if(out == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   if(Botan::EC_Group::supports_application_specific_group()) {
      *out = 1;
   } else {
      *out = 0;
   }
   return BOTAN_FFI_SUCCESS;
}

int botan_ec_group_supports_named_group(const char* name, int* out) {
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(name == nullptr || out == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }
      if(Botan::EC_Group::supports_named_group(name)) {
         *out = 1;
      } else {
         *out = 0;
      }
      return BOTAN_FFI_SUCCESS;
   });
}

int botan_ec_group_from_params(botan_ec_group_t* ec_group,
                               botan_asn1_oid_t oid,
                               botan_mp_t p,
                               botan_mp_t a,
                               botan_mp_t b,
                               botan_mp_t base_x,
                               botan_mp_t base_y,
                               botan_mp_t order) {
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(ec_group == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      Botan::EC_Group group(
         safe_get(oid), safe_get(p), safe_get(a), safe_get(b), safe_get(base_x), safe_get(base_y), safe_get(order));

      auto group_ptr = std::make_unique<Botan::EC_Group>(std::move(group));
      *ec_group = new botan_ec_group_struct(std::move(group_ptr));

      return BOTAN_FFI_SUCCESS;
   });
}

int botan_ec_group_from_ber(botan_ec_group_t* ec_group, const uint8_t* ber, size_t ber_len) {
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(ec_group == nullptr || ber == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      Botan::EC_Group group(ber, ber_len);

      auto group_ptr = std::make_unique<Botan::EC_Group>(std::move(group));
      *ec_group = new botan_ec_group_struct(std::move(group_ptr));

      return BOTAN_FFI_SUCCESS;
   });
}

int botan_ec_group_from_pem(botan_ec_group_t* ec_group, const char* pem) {
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(ec_group == nullptr || pem == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      Botan::EC_Group group = Botan::EC_Group::from_PEM(pem);

      auto group_ptr = std::make_unique<Botan::EC_Group>(std::move(group));
      *ec_group = new botan_ec_group_struct(std::move(group_ptr));

      return BOTAN_FFI_SUCCESS;
   });
}

int botan_ec_group_from_oid(botan_ec_group_t* ec_group, botan_asn1_oid_t oid) {
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(ec_group == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      Botan::EC_Group group = Botan::EC_Group::from_OID(safe_get(oid));

      auto group_ptr = std::make_unique<Botan::EC_Group>(std::move(group));
      *ec_group = new botan_ec_group_struct(std::move(group_ptr));

      return BOTAN_FFI_SUCCESS;
   });
}

int botan_ec_group_from_name(botan_ec_group_t* ec_group, const char* name) {
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(ec_group == nullptr || name == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      Botan::EC_Group group = Botan::EC_Group::from_name(name);

      auto group_ptr = std::make_unique<Botan::EC_Group>(std::move(group));
      *ec_group = new botan_ec_group_struct(std::move(group_ptr));

      return BOTAN_FFI_SUCCESS;
   });
}

int botan_ec_group_view_der(botan_ec_group_t ec_group, botan_view_ctx ctx, botan_view_bin_fn view) {
   return BOTAN_FFI_VISIT(ec_group,
                          [=](const auto& g) -> int { return invoke_view_callback(view, ctx, g.DER_encode()); });
}

int botan_ec_group_view_pem(botan_ec_group_t ec_group, botan_view_ctx ctx, botan_view_str_fn view) {
   return BOTAN_FFI_VISIT(ec_group, [=](const auto& g) -> int {
      return invoke_view_callback(view, ctx, g.PEM_encode(Botan::EC_Group_Encoding::NamedCurve));
   });
}

int botan_ec_group_get_curve_oid(botan_asn1_oid_t* oid, botan_ec_group_t ec_group) {
   return BOTAN_FFI_VISIT(ec_group, [=](const auto& g) -> int {
      if(oid == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }
      auto oid_ptr = std::make_unique<Botan::OID>(g.get_curve_oid());
      *oid = new botan_asn1_oid_struct(std::move(oid_ptr));

      return BOTAN_FFI_SUCCESS;
   });
}

namespace {
int botan_ec_group_get_component(botan_mp_t* out,
                                 botan_ec_group_t ec_group,
                                 const std::function<const Botan::BigInt&(const Botan::EC_Group&)>& getter) {
   return BOTAN_FFI_VISIT(ec_group, [=](const auto& g) -> int {
      if(out == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }
      auto val = std::make_unique<Botan::BigInt>(getter(g));
      *out = new botan_mp_struct(std::move(val));
      return BOTAN_FFI_SUCCESS;
   });
}
}  // namespace

int botan_ec_group_get_p(botan_mp_t* p, botan_ec_group_t ec_group) {
   return botan_ec_group_get_component(p, ec_group, [](const auto& g) -> const Botan::BigInt& { return g.get_p(); });
}

int botan_ec_group_get_a(botan_mp_t* a, botan_ec_group_t ec_group) {
   return botan_ec_group_get_component(a, ec_group, [](const auto& g) -> const Botan::BigInt& { return g.get_a(); });
}

int botan_ec_group_get_b(botan_mp_t* b, botan_ec_group_t ec_group) {
   return botan_ec_group_get_component(b, ec_group, [](const auto& g) -> const Botan::BigInt& { return g.get_b(); });
}

int botan_ec_group_get_g_x(botan_mp_t* g_x, botan_ec_group_t ec_group) {
   return botan_ec_group_get_component(
      g_x, ec_group, [](const auto& g) -> const Botan::BigInt& { return g.get_g_x(); });
}

int botan_ec_group_get_g_y(botan_mp_t* g_y, botan_ec_group_t ec_group) {
   return botan_ec_group_get_component(
      g_y, ec_group, [](const auto& g) -> const Botan::BigInt& { return g.get_g_y(); });
}

int botan_ec_group_get_order(botan_mp_t* order, botan_ec_group_t ec_group) {
   return botan_ec_group_get_component(
      order, ec_group, [](const auto& g) -> const Botan::BigInt& { return g.get_order(); });
}

int botan_ec_group_equal(botan_ec_group_t curve1_w, botan_ec_group_t curve2_w) {
   return BOTAN_FFI_VISIT(curve1_w, [=](const auto& curve1) -> int { return curve1 == safe_get(curve2_w); });
}
}
