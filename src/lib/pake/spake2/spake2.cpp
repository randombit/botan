/*
* (C) 2024,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/spake2.h>

#include <botan/hash.h>
#include <botan/hex.h>
#include <botan/pwdhash.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/mem_utils.h>
#include <botan/internal/stl_util.h>

namespace Botan::SPAKE2 {

namespace {

const EC_AffinePoint& spake2_our_pt(const Parameters& params, PeerId whoami) {
   return (whoami == PeerId::PeerA) ? params.spake2_m() : params.spake2_n();
}

const EC_AffinePoint& spake2_their_pt(const Parameters& params, PeerId whoami) {
   return (whoami == PeerId::PeerA) ? params.spake2_n() : params.spake2_m();
}

std::vector<uint8_t> format_spake2_ad(std::span<const uint8_t> a_identity,
                                      std::span<const uint8_t> b_identity,
                                      std::span<const uint8_t> context) {
   std::vector<uint8_t> ad(a_identity.size() + b_identity.size() + context.size() + 3 * 8);
   BufferStuffer stuffer(ad);

   auto append_with_le64 = [&](std::span<const uint8_t> data) {
      stuffer.append(store_le(static_cast<uint64_t>(data.size())));
      stuffer.append(data);
   };

   append_with_le64(a_identity);
   append_with_le64(b_identity);
   append_with_le64(context);
   return ad;
}

}  // namespace

EC_Scalar Parameters::hash_shared_secret(const EC_Group& group,
                                         std::string_view shared_secret,
                                         std::span<const uint8_t> a_identity,
                                         std::span<const uint8_t> b_identity,
                                         std::span<const uint8_t> context) {
   constexpr size_t M = 128 * 1024;
   constexpr size_t t = 3;
   constexpr size_t p = 1;

   const auto ad = format_spake2_ad(a_identity, b_identity, context);

   auto pwhash_fam = PasswordHashFamily::create_or_throw("Argon2id");
   auto pwhash = pwhash_fam->from_params(M, t, p);

   secure_vector<uint8_t> w_bytes(group.get_order_bytes() + 16);
   pwhash->hash(w_bytes, shared_secret, {}, ad, {});

   return EC_Scalar::from_bytes_mod_order(group, w_bytes);
}

Parameters::Parameters(const EC_Group& group,
                       std::string_view shared_secret,
                       std::span<const uint8_t> a_identity,
                       std::span<const uint8_t> b_identity,
                       std::span<const uint8_t> context,
                       std::string_view hash,
                       bool per_user_params) :
      Parameters(group,
                 Parameters::hash_shared_secret(group, shared_secret, a_identity, b_identity, context),
                 a_identity,
                 b_identity,
                 context,
                 hash,
                 per_user_params) {}

namespace {

std::pair<EC_AffinePoint, EC_AffinePoint> spake2_params(const EC_Group& group,
                                                        std::string_view hash_fn,
                                                        std::span<const uint8_t> a_identity,
                                                        std::span<const uint8_t> b_identity,
                                                        std::span<const uint8_t> context,
                                                        bool per_user_params) {
   BOTAN_ARG_CHECK(group.has_cofactor() == false, "SPAKE2 not supported with this curve");

   if(per_user_params) {
      auto input = format_spake2_ad(a_identity, b_identity, context);

      auto m = EC_AffinePoint::hash_to_curve_ro(group, hash_fn, input, cstr_as_span_of_bytes("SPAKE2 M"));
      auto n = EC_AffinePoint::hash_to_curve_ro(group, hash_fn, input, cstr_as_span_of_bytes("SPAKE2 N"));

      return std::make_pair(m, n);
   } else {
      const OID& group_id = group.get_curve_oid();

      auto decode_pt = [&](std::string_view pt) -> EC_AffinePoint { return EC_AffinePoint(group, hex_decode(pt)); };

      if(group_id == OID{1, 2, 840, 10045, 3, 1, 7}) {  // secp256r1
         auto m = decode_pt("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f");
         auto n = decode_pt("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49");
         return std::make_pair(m, n);
      } else if(group_id == OID{1, 3, 132, 0, 34}) {  // secp384r1
         auto m = decode_pt(
            "030ff0895ae5ebf6187080a82d82b42e2765e3b2f8749c7e05eba366434b363d3dc36f15314739074d2eb8613fceec2853");
         auto n = decode_pt(
            "02c72cf2e390853a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c543bb252c5490214cf9aa3f0baab4b665c10");
         return std::make_pair(m, n);
      } else if(group_id == OID{1, 3, 132, 0, 35}) {  // secp521r1
         auto m = decode_pt(
            "02003f06f38131b2ba2600791e82488e8d20ab889af753a41806c5db18d37d85608cfae06b82e4a72cd744c719193562a653ea1f119eef9356907edc9b56979962d7aa");
         auto n = decode_pt(
            "0200c7924b9ec017f3094562894336a53c50167ba8c5963876880542bc669e494b2532d76c5b53dfb349fdf69154b9e0048c58a42e8ed04cef052a3bc349d95575cd25");
         return std::make_pair(m, n);
      } else {
         throw Not_Implemented("There are no defined SPAKE2 parameters for this curve");
      }
   }
}

}  // namespace

Parameters::Parameters(const EC_Group& group,
                       const EC_Scalar& shared_secret,
                       std::span<const uint8_t> a_identity,
                       std::span<const uint8_t> b_identity,
                       std::span<const uint8_t> context,
                       std::string_view hash_fn,
                       bool per_user_params) :
      m_group(group),
      m_params(spake2_params(m_group, hash_fn, a_identity, b_identity, context, per_user_params)),
      m_w(shared_secret),
      m_hash_fn(hash_fn),
      m_a_identity(a_identity.begin(), a_identity.end()),
      m_b_identity(b_identity.begin(), b_identity.end()),
      m_context(context.begin(), context.end()) {}

std::vector<uint8_t> Context::generate_message() {
   BOTAN_STATE_CHECK(!m_our_message.has_value());

   const auto eph_key = EC_Scalar::random(m_params.group(), m_rng);

   const auto& N_or_M = spake2_our_pt(m_params, m_whoami);
   const auto& g = EC_AffinePoint::generator(m_params.group());
   // Compute g*x + w*{M,N}

   if(auto pt = EC_AffinePoint::mul_px_qy(g, eph_key, N_or_M, m_params.spake2_w(), m_rng)) {
      auto msg = pt->serialize_uncompressed();
      m_our_message = std::make_pair(msg, eph_key);
      return msg;
   } else {
      throw Internal_Error("Computed the identity element during SPAKE2 key exchange");
   }
}

secure_vector<uint8_t> Context::process_message(std::span<const uint8_t> peer_message) {
   BOTAN_STATE_CHECK(m_our_message.has_value());

   // Reject anything except uncompressed points
   if(peer_message.empty() || peer_message[0] != 0x04) {
      throw Decoding_Error("SPAKE2 key share was invalid");
   }

   // Will throw if not on the curve
   const EC_AffinePoint peer_pt(m_params.group(), peer_message);

   const auto& [our_pt, eph_key] = m_our_message.value();
   const auto& N_or_M = spake2_their_pt(m_params, m_whoami);
   // Compute x*(pt-w*N_or_M)
   const auto neg_xw = eph_key.negate() * m_params.spake2_w();
   const auto K = EC_AffinePoint::mul_px_qy(peer_pt, eph_key, N_or_M, neg_xw, m_rng);

   if(!K) {
      throw Internal_Error("Computed identity element during SPAKE2 key exchange");
   }

   auto hash = HashFunction::create_or_throw(m_params.hash_function());

   // Now we compute Hash(TT) as described in RFC 9382 section 3.3 and section 4

   auto append_to_hash_with_le64 = [&](std::span<const uint8_t> data) {
      hash->update(store_le(static_cast<uint64_t>(data.size())));
      hash->update(data);
   };

   // The context string is an extension to SPAKE2 (it is included in SPAKE2+)
   // To maintain RFC 9382 compatability we omit it if empty
   if(!m_params.context().empty()) {
      append_to_hash_with_le64(m_params.context());
   }

   append_to_hash_with_le64(m_params.a_identity());
   append_to_hash_with_le64(m_params.b_identity());

   // Always pA followed by pB:
   if(m_whoami == PeerId::PeerA) {
      append_to_hash_with_le64(our_pt);
      append_to_hash_with_le64(peer_message);
   } else {
      append_to_hash_with_le64(peer_message);
      append_to_hash_with_le64(our_pt);
   }

   append_to_hash_with_le64(K->serialize_uncompressed());
   append_to_hash_with_le64(m_params.spake2_w().serialize());

   m_our_message.reset();

   return hash->final();
}

}  // namespace Botan::SPAKE2
