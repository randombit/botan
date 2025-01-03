/*
 * Classic McEliece Parameters
 * (C) 2023 Jack Lloyd
 *     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/cmce_parameters.h>
#include <botan/internal/cmce_poly.h>

namespace Botan {

namespace {

CmceGfMod determine_poly_f(Classic_McEliece_Parameter_Set param_set) {
   switch(param_set.code()) {
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_348864:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_348864f:
         // z^12 + z^3 + 1
         return CmceGfMod(0b0001000000001001);
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_460896:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_460896f:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_6688128:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_6688128f:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_6688128pc:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_6688128pcf:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119f:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119pc:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119pcf:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_8192128:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_8192128f:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_8192128pc:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_8192128pcf:
         // z^12 + z^3 + 1
         return CmceGfMod(0b0010000000011011);
   }
   BOTAN_ASSERT_UNREACHABLE();
}

Classic_McEliece_Polynomial_Ring determine_poly_ring(Classic_McEliece_Parameter_Set param_set) {
   CmceGfMod poly_f = determine_poly_f(param_set);

   switch(param_set.code()) {
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_348864:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_348864f:
         // y^64 + y^3 + y + z
         return {{{3, Classic_McEliece_GF(CmceGfElem(1), poly_f)},
                  {1, Classic_McEliece_GF(CmceGfElem(1), poly_f)},
                  {0, Classic_McEliece_GF(CmceGfElem(2), poly_f)}},
                 poly_f,
                 64};
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_460896:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_460896f:
         // y^96 + y^10 + y^9 + y^6 + 1
         return {{{10, Classic_McEliece_GF(CmceGfElem(1), poly_f)},
                  {9, Classic_McEliece_GF(CmceGfElem(1), poly_f)},
                  {6, Classic_McEliece_GF(CmceGfElem(1), poly_f)},
                  {0, Classic_McEliece_GF(CmceGfElem(1), poly_f)}},
                 poly_f,
                 96};
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119f:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119pc:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119pcf:
         // y^119 + y^8 + 1
         // clang-format off
         return {{{8, Classic_McEliece_GF(CmceGfElem(1), poly_f)},
                  {0, Classic_McEliece_GF(CmceGfElem(1), poly_f)}},
                  poly_f,
                  119};
         // clang-format on
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_6688128:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_6688128f:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_6688128pc:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_6688128pcf:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_8192128:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_8192128f:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_8192128pc:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_8192128pcf:
         // y^128 + y^7 + y^2 + y + 1
         return {{{7, Classic_McEliece_GF(CmceGfElem(1), poly_f)},
                  {2, Classic_McEliece_GF(CmceGfElem(1), poly_f)},
                  {1, Classic_McEliece_GF(CmceGfElem(1), poly_f)},
                  {0, Classic_McEliece_GF(CmceGfElem(1), poly_f)}},
                 poly_f,
                 128};
   }
   BOTAN_ASSERT_UNREACHABLE();
}

}  //namespace

Classic_McEliece_Parameters Classic_McEliece_Parameters::create(Classic_McEliece_Parameter_Set set) {
   auto poly_ring = determine_poly_ring(set);

   switch(set.code()) {
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_348864:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_348864f:
         return Classic_McEliece_Parameters(set, 12, 3488, std::move(poly_ring));

      case Classic_McEliece_Parameter_Set::ClassicMcEliece_460896:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_460896f:
         return Classic_McEliece_Parameters(set, 13, 4608, std::move(poly_ring));

      case Classic_McEliece_Parameter_Set::ClassicMcEliece_6688128:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_6688128f:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_6688128pc:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_6688128pcf:
         return Classic_McEliece_Parameters(set, 13, 6688, std::move(poly_ring));

      case Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119f:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119pc:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119pcf:
         return Classic_McEliece_Parameters(set, 13, 6960, std::move(poly_ring));

      case Classic_McEliece_Parameter_Set::ClassicMcEliece_8192128:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_8192128f:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_8192128pc:
      case Classic_McEliece_Parameter_Set::ClassicMcEliece_8192128pcf:
         return Classic_McEliece_Parameters(set, 13, 8192, std::move(poly_ring));
   }
   BOTAN_ASSERT_UNREACHABLE();
}

Classic_McEliece_Parameters Classic_McEliece_Parameters::create(std::string_view name) {
   return Classic_McEliece_Parameters::create(Classic_McEliece_Parameter_Set::from_string(name));
}

Classic_McEliece_Parameters Classic_McEliece_Parameters::create(const OID& oid) {
   return create(Classic_McEliece_Parameter_Set::from_oid(oid));
}

OID Classic_McEliece_Parameters::object_identifier() const {
   return OID::from_string(m_set.to_string());
}

Classic_McEliece_Parameters::Classic_McEliece_Parameters(Classic_McEliece_Parameter_Set param_set,
                                                         size_t m,
                                                         size_t n,
                                                         Classic_McEliece_Polynomial_Ring poly_ring) :
      m_set(param_set), m_m(m), m_n(n), m_poly_ring(std::move(poly_ring)) {
   BOTAN_ASSERT(n % 8 == 0, "We require that n is a multiple of 8");
}

size_t Classic_McEliece_Parameters::estimated_strength() const {
   // Classic McEliece NIST Round 4 submission, Guide for security reviewers, Table 1:
   // For each instance, the minimal strength against the best attack (with free memory access)
   // is used as the overall security strength estimate. The strength is capped at 256, since the
   // seed is only 256 bits long.
   switch(m_set.code()) {
      case Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_348864:
      case Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_348864f:
         return 140;
      case Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_460896:
      case Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_460896f:
         return 179;
      case Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_6688128:
      case Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_6688128f:
      case Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_6688128pc:
      case Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_6688128pcf:
         return 246;
      case Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119:
      case Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119f:
      case Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119pc:
      case Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119pcf:
         return 245;
      case Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_8192128:
      case Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_8192128f:
      case Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_8192128pc:
      case Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_8192128pcf:
         return 256;  // 275 in the document. Capped at 256 because of the seed length.
   }
   BOTAN_ASSERT_UNREACHABLE();
}

std::unique_ptr<XOF> Classic_McEliece_Parameters::prg(std::span<const uint8_t> seed) const {
   BOTAN_ASSERT_EQUAL(seed.size(), 32, "Valid seed length");
   auto xof = XOF::create_or_throw("SHAKE-256");

   xof->update(std::array<uint8_t, 1>({64}));
   xof->update(seed);

   return xof;
}

}  // namespace Botan
