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
      return ffi_new_object(ec_group, std::move(group_ptr));
   });
}

int botan_ec_group_from_ber(botan_ec_group_t* ec_group, const uint8_t* ber, size_t ber_len) {
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(ec_group == nullptr || ber == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      Botan::EC_Group group(ber, ber_len);

      auto group_ptr = std::make_unique<Botan::EC_Group>(std::move(group));
      return ffi_new_object(ec_group, std::move(group_ptr));
   });
}

int botan_ec_group_from_pem(botan_ec_group_t* ec_group, const char* pem) {
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(ec_group == nullptr || pem == nullptr) {
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
      if(ec_group == nullptr || name == nullptr) {
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

int botan_ec_group_get_generator(botan_ec_group_t ec_group, botan_ec_point_t* generator) {
   if(Botan::any_null_pointers(generator)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(ec_group, [=](const auto& g) -> int {
      Botan::EC_AffinePoint pt = Botan::EC_AffinePoint::generator(g);
      return ffi_new_object(generator, std::make_unique<Botan::EC_AffinePoint>(std::move(pt)));
   });
}

int botan_ec_group_get_identity(botan_ec_group_t ec_group, botan_ec_point_t* identity) {
   if(Botan::any_null_pointers(identity)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(ec_group, [=](const auto& g) -> int {
      Botan::EC_AffinePoint pt = Botan::EC_AffinePoint::identity(g);
      return ffi_new_object(identity, std::make_unique<Botan::EC_AffinePoint>(std::move(pt)));
   });
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

int botan_ec_scalar_one(botan_ec_scalar_t* ec_scalar, botan_ec_group_t ec_group) {
   if(Botan::any_null_pointers(ec_scalar)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(ec_group, [=](const auto& g) -> int {
      return ffi_new_object(ec_scalar, std::make_unique<Botan::EC_Scalar>(Botan::EC_Scalar::one(g)));
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

int botan_ec_scalar_view_bytes(botan_ec_scalar_t ec_scalar, botan_view_ctx ctx, botan_view_bin_fn view) {
   return BOTAN_FFI_VISIT(ec_scalar, [=](const auto& s) -> int {
      auto bytes = s.serialize();
      return invoke_view_callback(view, ctx, bytes);
   });
}

int botan_ec_scalar_to_mp(botan_ec_scalar_t ec_scalar, botan_mp_t* mp) {
   if(Botan::any_null_pointers(mp)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(ec_scalar, [=](const auto& s) -> int {
      return ffi_new_object(mp, std::make_unique<Botan::BigInt>(s.to_bigint()));
   });
}

int botan_ec_scalar_is_zero(botan_ec_scalar_t ec_scalar) {
   return BOTAN_FFI_VISIT(ec_scalar, [=](const auto& s) -> int { return s.is_zero() ? 1 : 0; });
}

int botan_ec_scalar_is_nonzero(botan_ec_scalar_t ec_scalar) {
   return BOTAN_FFI_VISIT(ec_scalar, [=](const auto& s) -> int { return s.is_nonzero() ? 1 : 0; });
}

int botan_ec_scalar_is_eq(botan_ec_scalar_t ec_scalar, botan_ec_scalar_t x) {
   return BOTAN_FFI_VISIT(ec_scalar, [=](const auto& s) -> int { return s.is_eq(safe_get(x)) ? 1 : 0; });
}

int botan_ec_scalar_gk_x_mod_order(botan_ec_scalar_t ec_scalar, botan_rng_t rng, botan_ec_scalar_t* res) {
   if(Botan::any_null_pointers(res)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(ec_scalar, [=](const auto& s) {
      return ffi_new_object(res,
                            std::make_unique<Botan::EC_Scalar>(Botan::EC_Scalar::gk_x_mod_order(s, safe_get(rng))));
   });
}

int botan_ec_scalar_g_mul(botan_ec_scalar_t scalar, botan_rng_t rng, botan_ec_point_t* res) {
   if(Botan::any_null_pointers(res)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::EC_AffinePoint pt = Botan::EC_AffinePoint::g_mul(safe_get(scalar), safe_get(rng));
      return ffi_new_object(res, std::make_unique<Botan::EC_AffinePoint>(pt));
   });
}

int botan_ec_scalar_invert(botan_ec_scalar_t ec_scalar, botan_ec_scalar_t* res) {
   if(Botan::any_null_pointers(res)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(ec_scalar, [=](const auto& s) -> int {
      return ffi_new_object(res, std::make_unique<Botan::EC_Scalar>(s.invert()));
   });
}

int botan_ec_scalar_invert_vartime(botan_ec_scalar_t ec_scalar, botan_ec_scalar_t* res) {
   if(Botan::any_null_pointers(res)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(ec_scalar, [=](const auto& s) -> int {
      return ffi_new_object(res, std::make_unique<Botan::EC_Scalar>(s.invert_vartime()));
   });
}

int botan_ec_scalar_negate(botan_ec_scalar_t ec_scalar, botan_ec_scalar_t* res) {
   if(Botan::any_null_pointers(res)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(ec_scalar, [=](const auto& s) -> int {
      return ffi_new_object(res, std::make_unique<Botan::EC_Scalar>(s.negate()));
   });
}

int botan_ec_scalar_add(botan_ec_scalar_t ec_scalar, botan_ec_scalar_t x, botan_ec_scalar_t* res) {
   if(Botan::any_null_pointers(res)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(ec_scalar, [=](const auto& s) -> int {
      return ffi_new_object(res, std::make_unique<Botan::EC_Scalar>(s.add(safe_get(x))));
   });
}

int botan_ec_scalar_sub(botan_ec_scalar_t ec_scalar, botan_ec_scalar_t x, botan_ec_scalar_t* res) {
   if(Botan::any_null_pointers(res)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(ec_scalar, [=](const auto& s) -> int {
      return ffi_new_object(res, std::make_unique<Botan::EC_Scalar>(s.sub(safe_get(x))));
   });
}

int botan_ec_scalar_mul(botan_ec_scalar_t ec_scalar, botan_ec_scalar_t x, botan_ec_scalar_t* res) {
   if(Botan::any_null_pointers(res)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(ec_scalar, [=](const auto& s) -> int {
      return ffi_new_object(res, std::make_unique<Botan::EC_Scalar>(s.mul(safe_get(x))));
   });
}

int botan_ec_scalar_square(botan_ec_scalar_t ec_scalar) {
   return BOTAN_FFI_VISIT(ec_scalar, [=](auto& s) -> int {
      s.square_self();
      return BOTAN_FFI_SUCCESS;
   });
}

// ec points

int botan_ec_point_destroy(botan_ec_point_t ec_point) {
   return BOTAN_FFI_CHECKED_DELETE(ec_point);
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

int botan_ec_point_is_eq(botan_ec_point_t ec_point, botan_ec_point_t other) {
   return BOTAN_FFI_VISIT(ec_point, [=](const auto& p) -> int { return p == safe_get(other) ? 1 : 0; });
}

int botan_ec_point_mul(botan_ec_point_t ec_point, botan_ec_scalar_t scalar, botan_rng_t rng, botan_ec_point_t* res) {
   if(Botan::any_null_pointers(res)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(ec_point, [=](auto& pt) -> int {
      Botan::EC_AffinePoint out = pt.mul(safe_get(scalar), safe_get(rng));
      return ffi_new_object(res, std::make_unique<Botan::EC_AffinePoint>(out));
   });
}

int botan_ec_point_negate(botan_ec_point_t ec_point, botan_ec_point_t* res) {
   if(Botan::any_null_pointers(res)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(ec_point, [=](auto& pt) -> int {
      Botan::EC_AffinePoint out = pt.negate();
      return ffi_new_object(res, std::make_unique<Botan::EC_AffinePoint>(out));
   });
}

int botan_ec_point_add(botan_ec_point_t ec_point, botan_ec_point_t q, botan_ec_point_t* res) {
   if(Botan::any_null_pointers(res)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(ec_point, [=](auto& pt) -> int {
      Botan::EC_AffinePoint out = pt.add(safe_get(q));
      return ffi_new_object(res, std::make_unique<Botan::EC_AffinePoint>(out));
   });
}
}
