/*
* (C) 2025 Jack Lloyd
* (C) 2025,2026 Dominik Schricker
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>

#include <botan/internal/ffi_ec.h>
#include <botan/internal/ffi_mp.h>
#include <botan/internal/ffi_oid.h>
#include <botan/internal/ffi_rng.h>
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
      if(Botan::any_null_pointers(name, out)) {
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
      return ffi_new_object(ec_group, std::move(group_ptr));
   });
}

int botan_ec_group_from_ber(botan_ec_group_t* ec_group, const uint8_t* ber, size_t ber_len) {
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(Botan::any_null_pointers(ec_group, ber)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      Botan::EC_Group group(ber, ber_len);

      auto group_ptr = std::make_unique<Botan::EC_Group>(std::move(group));
      return ffi_new_object(ec_group, std::move(group_ptr));
   });
}

int botan_ec_group_from_pem(botan_ec_group_t* ec_group, const char* pem) {
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(Botan::any_null_pointers(ec_group, pem)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      Botan::EC_Group group = Botan::EC_Group::from_PEM(pem);

      auto group_ptr = std::make_unique<Botan::EC_Group>(std::move(group));
      return ffi_new_object(ec_group, std::move(group_ptr));
   });
}

int botan_ec_group_from_oid(botan_ec_group_t* ec_group, botan_asn1_oid_t oid) {
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(ec_group == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      Botan::EC_Group group = Botan::EC_Group::from_OID(safe_get(oid));

      auto group_ptr = std::make_unique<Botan::EC_Group>(std::move(group));
      return ffi_new_object(ec_group, std::move(group_ptr));
   });
}

int botan_ec_group_from_name(botan_ec_group_t* ec_group, const char* name) {
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(Botan::any_null_pointers(ec_group, name)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      Botan::EC_Group group = Botan::EC_Group::from_name(name);

      auto group_ptr = std::make_unique<Botan::EC_Group>(std::move(group));
      return ffi_new_object(ec_group, std::move(group_ptr));
   });
}

int botan_ec_group_unregister(botan_asn1_oid_t oid) {
   return BOTAN_FFI_VISIT(oid, [=](const auto& o) -> int { return Botan::EC_Group::unregister(o) ? 1 : 0; });
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
      return ffi_new_object(oid, std::move(oid_ptr));
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
      return ffi_new_object(out, std::move(val));
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

// ec scalars

int botan_ec_scalar_destroy(botan_ec_scalar_t ec_scalar) {
   return BOTAN_FFI_CHECKED_DELETE(ec_scalar);
}

int botan_ec_scalar_random(botan_ec_scalar_t* ec_scalar, botan_ec_group_t ec_group, botan_rng_t rng) {
   if(Botan::any_null_pointers(ec_scalar)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(ec_group, [=](const auto& g) -> int {
      return ffi_new_object(ec_scalar, std::make_unique<Botan::EC_Scalar>(Botan::EC_Scalar::random(g, safe_get(rng))));
   });
}

int botan_ec_scalar_from_mp(botan_ec_scalar_t* ec_scalar, botan_ec_group_t ec_group, botan_mp_t mp) {
   if(Botan::any_null_pointers(ec_scalar)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(ec_group, [=](const auto& g) -> int {
      return ffi_new_object(ec_scalar,
                            std::make_unique<Botan::EC_Scalar>(Botan::EC_Scalar::from_bigint(g, safe_get(mp))));
   });
}

int botan_ec_scalar_to_mp(botan_ec_scalar_t ec_scalar, botan_mp_t* mp) {
   if(Botan::any_null_pointers(mp)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(ec_scalar, [=](const auto& sc) -> int {
      return ffi_new_object(mp, std::make_unique<Botan::BigInt>(sc.to_bigint()));
   });
}

// ec points

int botan_ec_point_destroy(botan_ec_point_t ec_point) {
   return BOTAN_FFI_CHECKED_DELETE(ec_point);
}

int botan_ec_point_identity(botan_ec_point_t* ec_point, botan_ec_group_t ec_group) {
   if(Botan::any_null_pointers(ec_point)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(ec_group, [=](const auto& g) -> int {
      return ffi_new_object(ec_point, std::make_unique<Botan::EC_AffinePoint>(Botan::EC_AffinePoint::identity(g)));
   });
}

int botan_ec_point_generator(botan_ec_point_t* ec_point, botan_ec_group_t ec_group) {
   if(Botan::any_null_pointers(ec_point)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(ec_group, [=](const auto& g) -> int {
      return ffi_new_object(ec_point, std::make_unique<Botan::EC_AffinePoint>(Botan::EC_AffinePoint::generator(g)));
   });
}

int botan_ec_point_from_xy(botan_ec_point_t* ec_point, botan_ec_group_t ec_group, botan_mp_t x, botan_mp_t y) {
   if(Botan::any_null_pointers(ec_point)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return ffi_guard_thunk(__func__, [=]() -> int {
      std::optional<Botan::EC_AffinePoint> pt =
         Botan::EC_AffinePoint::from_bigint_xy(safe_get(ec_group), safe_get(x), safe_get(y));
      if(!pt.has_value()) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }

      return ffi_new_object(ec_point, std::make_unique<Botan::EC_AffinePoint>(pt.value()));
   });
}

int botan_ec_point_from_bytes(botan_ec_point_t* ec_point,
                              botan_ec_group_t ec_group,
                              const uint8_t* bytes,
                              size_t bytes_len) {
   if(Botan::any_null_pointers(ec_point, bytes)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(ec_group, [=](const auto& g) -> int {
      Botan::EC_AffinePoint pt(g, std::span{bytes, bytes_len});
      return ffi_new_object(ec_point, std::make_unique<Botan::EC_AffinePoint>(std::move(pt)));
   });
}

int botan_ec_point_view_x_bytes(botan_ec_point_t ec_point, botan_view_ctx ctx, botan_view_bin_fn view) {
   return BOTAN_FFI_VISIT(ec_point, [=](const auto& p) -> int {
      auto bytes = p.x_bytes();
      return invoke_view_callback(view, ctx, bytes);
   });
}

int botan_ec_point_view_y_bytes(botan_ec_point_t ec_point, botan_view_ctx ctx, botan_view_bin_fn view) {
   return BOTAN_FFI_VISIT(ec_point, [=](const auto& p) -> int {
      auto bytes = p.y_bytes();
      return invoke_view_callback(view, ctx, bytes);
   });
}

int botan_ec_point_view_xy_bytes(botan_ec_point_t ec_point, botan_view_ctx ctx, botan_view_bin_fn view) {
   return BOTAN_FFI_VISIT(ec_point, [=](const auto& p) -> int {
      auto bytes = p.xy_bytes();
      return invoke_view_callback(view, ctx, bytes);
   });
}

int botan_ec_point_view_uncompressed(botan_ec_point_t ec_point, botan_view_ctx ctx, botan_view_bin_fn view) {
   return BOTAN_FFI_VISIT(ec_point, [=](const auto& p) -> int {
      auto bytes = p.serialize_uncompressed();
      return invoke_view_callback(view, ctx, bytes);
   });
}

int botan_ec_point_view_compressed(botan_ec_point_t ec_point, botan_view_ctx ctx, botan_view_bin_fn view) {
   return BOTAN_FFI_VISIT(ec_point, [=](const auto& p) -> int {
      auto bytes = p.serialize_compressed();
      return invoke_view_callback(view, ctx, bytes);
   });
}

int botan_ec_point_is_identity(botan_ec_point_t ec_point) {
   return BOTAN_FFI_VISIT(ec_point, [=](const auto& p) -> int { return p.is_identity() ? 1 : 0; });
}

int botan_ec_point_equal(botan_ec_point_t x_w, botan_ec_point_t y_w) {
   return BOTAN_FFI_VISIT(x_w, [=](const auto& x) -> int { return x == safe_get(y_w) ? 1 : 0; });
}

int botan_ec_point_mul(botan_ec_point_t* result,
                       botan_ec_point_t ec_point,
                       botan_ec_scalar_t ec_scalar,
                       botan_rng_t rng) {
   if(Botan::any_null_pointers(result)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(ec_point, [=](auto& pt) -> int {
      Botan::EC_AffinePoint res = pt.mul(safe_get(ec_scalar), safe_get(rng));
      return ffi_new_object(result, std::make_unique<Botan::EC_AffinePoint>(std::move(res)));
   });
}

int botan_ec_point_negate(botan_ec_point_t* result, botan_ec_point_t ec_point) {
   if(Botan::any_null_pointers(result)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(ec_point, [=](auto& pt) -> int {
      Botan::EC_AffinePoint res = pt.negate();
      return ffi_new_object(result, std::make_unique<Botan::EC_AffinePoint>(std::move(res)));
   });
}

int botan_ec_point_add(botan_ec_point_t* result, botan_ec_point_t x_w, botan_ec_point_t y_w) {
   if(Botan::any_null_pointers(result)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(x_w, [=](auto& x) -> int {
      Botan::EC_AffinePoint res = x.add(safe_get(y_w));
      return ffi_new_object(result, std::make_unique<Botan::EC_AffinePoint>(std::move(res)));
   });
}
}
