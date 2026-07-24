/*
* (C) 2024,2025,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/spake2p.h>

#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include <botan/kdf.h>
#include <botan/mac.h>
#include <botan/mem_ops.h>
#include <botan/pwdhash.h>
#include <botan/internal/buffer_stuffer.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/mem_utils.h>

namespace Botan::SPAKE2p {

namespace {

std::array<uint8_t, 8> le64_length(std::span<const uint8_t> data) {
   return store_le(static_cast<uint64_t>(data.size()));
}

std::pair<EC_Scalar, EC_Scalar> derive_w0_w1(const SystemParameters& params,
                                             std::string_view password,
                                             std::span<const uint8_t> prover_id,
                                             std::span<const uint8_t> verifier_id,
                                             std::span<const uint8_t> salt) {
   /*
   * RFC 9383 Section 3.2
   *
   *    w0s || w1s = PBKDF(len(pw) || pw ||
   *                       len(idProver) || idProver ||
   *                       len(idVerifier) || idVerifier)
   *    w0 = w0s mod p
   *    w1 = w1s mod p
   */
   secure_vector<uint8_t> pbkdf_input(3 * 8 + password.size() + prover_id.size() + verifier_id.size());
   BufferStuffer stuffer(pbkdf_input);

   auto append_with_le64_length = [&](std::span<const uint8_t> data) {
      stuffer.append(le64_length(data));
      stuffer.append(data);
   };

   append_with_le64_length(as_span_of_bytes(password));
   append_with_le64_length(prover_id);
   append_with_le64_length(verifier_id);
   BOTAN_ASSERT_NOMSG(stuffer.full());

   /*
   * RFC 9106 Section 4
   *
   *    If much less memory is available, a uniformly safe option is
   *    Argon2id with t=3 iterations, p=4 lanes, m=2^(16) (64 MiB of RAM)
   */
   auto pwhash = PasswordHashFamily::create_or_throw("Argon2id")->from_params(64 * 1024, 3, 4);

   /*
   * RFC 9383 Section 3.2
   *
   *    To control bias, each half must be of length at least
   *    ceil(log2(p)) + k bits, with k >= 64
   */
   const size_t half_len = params.group().get_order_bytes() + 16;

   secure_vector<uint8_t> w0s_w1s(2 * half_len);
   const std::string_view pbkdf_input_sv(cast_uint8_ptr_to_char(pbkdf_input.data()), pbkdf_input.size());
   pwhash->hash(w0s_w1s, pbkdf_input_sv, salt);

   auto w0 = EC_Scalar::from_bytes_mod_order(params.group(), std::span{w0s_w1s}.first(half_len));
   auto w1 = EC_Scalar::from_bytes_mod_order(params.group(), std::span{w0s_w1s}.last(half_len));

   return {std::move(w0), std::move(w1)};
}

struct SessionKeys {
      secure_vector<uint8_t> shared_key;
      std::vector<uint8_t> confirm_p;
      std::vector<uint8_t> confirm_v;
};

SessionKeys spake2p_key_schedule(const SystemParameters& params,
                                 std::span<const uint8_t> context,
                                 std::span<const uint8_t> prover_id,
                                 std::span<const uint8_t> verifier_id,
                                 std::span<const uint8_t> share_p,
                                 std::span<const uint8_t> share_v,
                                 const EC_AffinePoint& z,
                                 const EC_AffinePoint& v,
                                 const EC_Scalar& w0) {
   auto hash = HashFunction::create_or_throw(params.hash_function());

   auto hash_with_le64_length = [&](std::span<const uint8_t> data) {
      hash->update(le64_length(data));
      hash->update(data);
   };

   /*
   * RFC 9383 Section 3.3
   *
   *    TT = len(Context) || Context
   *      || len(idProver) || idProver
   *      || len(idVerifier) || idVerifier
   *      || len(M) || M
   *      || len(N) || N
   *      || len(shareP) || shareP
   *      || len(shareV) || shareV
   *      || len(Z) || Z
   *      || len(V) || V
   *      || len(w0) || w0
   */
   hash_with_le64_length(context);
   hash_with_le64_length(prover_id);
   hash_with_le64_length(verifier_id);
   hash_with_le64_length(params.spake2p_m().serialize_uncompressed());
   hash_with_le64_length(params.spake2p_n().serialize_uncompressed());
   hash_with_le64_length(share_p);
   hash_with_le64_length(share_v);
   hash_with_le64_length(z.serialize_uncompressed());
   hash_with_le64_length(v.serialize_uncompressed());
   hash_with_le64_length(w0.serialize());

   const auto k_main = hash->final();

   /*
   * RFC 9383 Section 3.4
   *
   *    K_main = Hash(TT)
   *    K_confirmP || K_confirmV = KDF(nil, K_main, "ConfirmationKeys")
   *    K_shared = KDF(nil, K_main, "SharedKey")
   *
   *    confirmP = MAC(K_confirmP, shareV)
   *    confirmV = MAC(K_confirmV, shareP)
   */
   auto kdf = KDF::create_or_throw(fmt("HKDF({})", params.hash_function()));
   auto mac = MessageAuthenticationCode::create_or_throw(fmt("HMAC({})", params.hash_function()));

   const size_t mac_key_len = hash->output_length();
   const auto confirm_keys = kdf->derive_key<secure_vector<uint8_t>>(2 * mac_key_len, k_main, "", "ConfirmationKeys");

   SessionKeys keys;
   keys.shared_key = kdf->derive_key<secure_vector<uint8_t>>(hash->output_length(), k_main, "", "SharedKey");

   mac->set_key(std::span{confirm_keys}.first(mac_key_len));
   mac->update(share_v);
   keys.confirm_p = mac->final_stdvec();

   mac->set_key(std::span{confirm_keys}.last(mac_key_len));
   mac->update(share_p);
   keys.confirm_v = mac->final_stdvec();

   return keys;
}

std::tuple<EC_Group, EC_AffinePoint, EC_AffinePoint> spake2p_group_params(std::string_view group_name,
                                                                          std::string_view m_hex,
                                                                          std::string_view n_hex) {
   auto group = EC_Group::from_name(group_name);
   EC_AffinePoint m(group, hex_decode(m_hex));
   EC_AffinePoint n(group, hex_decode(n_hex));
   return {std::move(group), std::move(m), std::move(n)};
}

// The M/N constants from RFC 9383 Section 4

constexpr std::string_view SPAKE2P_P256_M = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";

constexpr std::string_view SPAKE2P_P256_N = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";

constexpr std::string_view SPAKE2P_P384_M =
   "030ff0895ae5ebf6187080a82d82b42e2765e3b2f8749c7e05eba366434b363d3dc36f15314739074d2eb8613fceec2853";

constexpr std::string_view SPAKE2P_P384_N =
   "02c72cf2e390853a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c543bb252c5490214cf9aa3f0baab4b665c10";

constexpr std::string_view SPAKE2P_P521_M =
   "02003f06f38131b2ba2600791e82488e8d20ab889af753a41806c5db18d37d85608cfae06b82e4a72cd744c719193562a653ea1f119ee"
   "f9356907edc9b56979962d7aa";

constexpr std::string_view SPAKE2P_P521_N =
   "0200c7924b9ec017f3094562894336a53c50167ba8c5963876880542bc669e494b2532d76c5b53dfb349fdf69154b9e0048c58a42e8ed"
   "04cef052a3bc349d95575cd25";

}  // namespace

SystemParameters::SystemParameters(EC_Group group, EC_AffinePoint m, EC_AffinePoint n, std::string_view hash_fn) :
      m_group(std::move(group)), m_spake2p_m(std::move(m)), m_spake2p_n(std::move(n)), m_hash_fn(hash_fn) {}

SystemParameters SystemParameters::rfc9383_p256_sha256() {
   auto [group, m, n] = spake2p_group_params("secp256r1", SPAKE2P_P256_M, SPAKE2P_P256_N);
   return SystemParameters(std::move(group), std::move(m), std::move(n), "SHA-256");
}

SystemParameters SystemParameters::rfc9383_p256_sha512() {
   auto [group, m, n] = spake2p_group_params("secp256r1", SPAKE2P_P256_M, SPAKE2P_P256_N);
   return SystemParameters(std::move(group), std::move(m), std::move(n), "SHA-512");
}

SystemParameters SystemParameters::rfc9383_p384_sha256() {
   auto [group, m, n] = spake2p_group_params("secp384r1", SPAKE2P_P384_M, SPAKE2P_P384_N);
   return SystemParameters(std::move(group), std::move(m), std::move(n), "SHA-256");
}

SystemParameters SystemParameters::rfc9383_p384_sha512() {
   auto [group, m, n] = spake2p_group_params("secp384r1", SPAKE2P_P384_M, SPAKE2P_P384_N);
   return SystemParameters(std::move(group), std::move(m), std::move(n), "SHA-512");
}

SystemParameters SystemParameters::rfc9383_p521_sha512() {
   auto [group, m, n] = spake2p_group_params("secp521r1", SPAKE2P_P521_M, SPAKE2P_P521_N);
   return SystemParameters(std::move(group), std::move(m), std::move(n), "SHA-512");
}

SystemParameters SystemParameters::custom(const EC_Group& group,
                                          std::span<const uint8_t> seed,
                                          std::string_view hash_fn) {
   BOTAN_ARG_CHECK(group.has_cofactor() == false, "SPAKE2+ is not supported for groups with a cofactor");

   auto m = EC_AffinePoint::hash_to_curve_ro(group, hash_fn, seed, "SPAKE2+ M");
   auto n = EC_AffinePoint::hash_to_curve_ro(group, hash_fn, seed, "SPAKE2+ N");

   return SystemParameters(group, std::move(m), std::move(n), hash_fn);
}

size_t SystemParameters::share_size() const {
   return 1 + 2 * m_group.get_p_bytes();
}

size_t SystemParameters::confirmation_size() const {
   if(m_hash_fn == "SHA-256") {
      return 32;
   } else if(m_hash_fn == "SHA-384") {
      return 48;
   } else if(m_hash_fn == "SHA-512") {
      return 64;
   } else {
      return HashFunction::create_or_throw(m_hash_fn)->output_length();
   }
}

RegistrationRecord RegistrationRecord::from_password(const SystemParameters& params,
                                                     std::string_view password,
                                                     std::span<const uint8_t> prover_id,
                                                     std::span<const uint8_t> verifier_id,
                                                     std::span<const uint8_t> salt,
                                                     RandomNumberGenerator& rng) {
   return ProverSecret::from_password(params, password, prover_id, verifier_id, salt).registration_record(rng);
}

RegistrationRecord RegistrationRecord::deserialize(const SystemParameters& params, std::span<const uint8_t> record) {
   const size_t scalar_len = params.group().get_order_bytes();
   const size_t point_len = params.share_size();

   if(record.size() != scalar_len + point_len) {
      throw Decoding_Error("Invalid length for SPAKE2+ registration record");
   }

   auto w0 = EC_Scalar::deserialize(params.group(), record.first(scalar_len));
   auto l = EC_AffinePoint::deserialize_uncompressed(params.group(), record.subspan(scalar_len));

   if(!w0 || !l) {
      throw Decoding_Error("Invalid SPAKE2+ registration record");
   }

   return RegistrationRecord(std::move(*w0), std::move(*l));
}

secure_vector<uint8_t> RegistrationRecord::serialize() const {
   return concat<secure_vector<uint8_t>>(m_w0.serialize(), m_l.serialize_uncompressed());
}

ProverSecret ProverSecret::from_password(const SystemParameters& params,
                                         std::string_view password,
                                         std::span<const uint8_t> prover_id,
                                         std::span<const uint8_t> verifier_id,
                                         std::span<const uint8_t> salt) {
   auto [w0, w1] = derive_w0_w1(params, password, prover_id, verifier_id, salt);
   return ProverSecret(std::move(w0), std::move(w1));
}

ProverSecret ProverSecret::from_prehashed(EC_Scalar w0, EC_Scalar w1) {
   return ProverSecret(std::move(w0), std::move(w1));
}

ProverSecret ProverSecret::deserialize(const SystemParameters& params, std::span<const uint8_t> secret) {
   if(auto w0_w1 = EC_Scalar::deserialize_pair(params.group(), secret)) {
      return ProverSecret(std::move(w0_w1->first), std::move(w0_w1->second));
   } else {
      throw Decoding_Error("Invalid SPAKE2+ prover secret");
   }
}

secure_vector<uint8_t> ProverSecret::serialize() const {
   return EC_Scalar::serialize_pair<secure_vector<uint8_t>>(m_w0, m_w1);
}

RegistrationRecord ProverSecret::registration_record(RandomNumberGenerator& rng) const {
   // RFC 9383 Section 3.2: "the registration record L=w1*P"
   return RegistrationRecord(m_w0, EC_AffinePoint::g_mul(m_w1, rng));
}

ProverContext::ProverContext(const SystemParameters& params,
                             const ProverSecret& secret,
                             std::span<const uint8_t> prover_id,
                             std::span<const uint8_t> verifier_id,
                             std::span<const uint8_t> context) :
      m_params(params),
      m_secret(secret),
      m_prover_id(prover_id.begin(), prover_id.end()),
      m_verifier_id(verifier_id.begin(), verifier_id.end()),
      m_context(context.begin(), context.end()) {}

std::vector<uint8_t> ProverContext::generate_message(RandomNumberGenerator& rng) {
   BOTAN_STATE_CHECK(m_state == State::Initial);

   const auto x = EC_Scalar::random(m_params.group(), rng);
   const auto g = EC_AffinePoint::generator(m_params.group());

   // RFC 9383 Section 3.3: X = x*P + w0*M
   if(auto share_p = EC_AffinePoint::mul_px_qy(g, x, m_params.spake2p_m(), m_secret.m_w0, rng)) {
      m_our_message = std::make_pair(share_p->serialize_uncompressed(), x);
      m_state = State::ShareGenerated;
      return m_our_message->first;
   } else {
      throw Internal_Error("Computed the identity element during SPAKE2+ key exchange");
   }
}

std::vector<uint8_t> ProverContext::process_message(std::span<const uint8_t> peer_message, RandomNumberGenerator& rng) {
   BOTAN_STATE_CHECK(m_state == State::ShareGenerated);

   const size_t share_size = m_params.share_size();
   const size_t confirm_size = m_params.confirmation_size();

   if(peer_message.size() != share_size + confirm_size) {
      throw Decoding_Error("Invalid length for SPAKE2+ verifier message");
   }

   const auto share_v = peer_message.first(share_size);
   const auto confirm_v = peer_message.subspan(share_size);

   const auto y = EC_AffinePoint::deserialize_uncompressed(m_params.group(), share_v);
   if(!y) {
      throw Decoding_Error("Invalid SPAKE2+ key share");
   }

   const auto& w0 = m_secret.m_w0;
   const auto& w1 = m_secret.m_w1;
   const auto& n = m_params.spake2p_n();
   const auto& x = m_our_message->second;

   // RFC 9383 Section 3.3: Z = h*x*(Y - w0*N), V = h*w1*(Y - w0*N)
   const auto z = EC_AffinePoint::mul_px_qy(*y, x, n, (x * w0).negate(), rng);
   const auto v = EC_AffinePoint::mul_px_qy(*y, w1, n, (w1 * w0).negate(), rng);

   if(!z || !v) {
      throw Decoding_Error("Invalid SPAKE2+ key share");
   }

   auto keys =
      spake2p_key_schedule(m_params, m_context, m_prover_id, m_verifier_id, m_our_message->first, share_v, *z, *v, w0);

   if(!constant_time_compare(keys.confirm_v, confirm_v)) {
      m_our_message.reset();
      m_state = State::Failed;
      throw Invalid_Authentication_Tag("SPAKE2+ key confirmation failed");
   }

   m_shared_secret = std::move(keys.shared_key);
   m_our_message.reset();
   m_state = State::Complete;

   return keys.confirm_p;
}

secure_vector<uint8_t> ProverContext::shared_secret() const {
   BOTAN_STATE_CHECK(m_state == State::Complete);
   return m_shared_secret;
}

VerifierContext::VerifierContext(const SystemParameters& params,
                                 const RegistrationRecord& record,
                                 std::span<const uint8_t> prover_id,
                                 std::span<const uint8_t> verifier_id,
                                 std::span<const uint8_t> context) :
      m_params(params),
      m_record(record),
      m_prover_id(prover_id.begin(), prover_id.end()),
      m_verifier_id(verifier_id.begin(), verifier_id.end()),
      m_context(context.begin(), context.end()) {}

std::vector<uint8_t> VerifierContext::process_message(std::span<const uint8_t> peer_message,
                                                      RandomNumberGenerator& rng) {
   BOTAN_STATE_CHECK(m_state == State::Initial);

   // Reject anything except uncompressed points
   if(peer_message.size() != m_params.share_size() || peer_message[0] != 0x04) {
      throw Decoding_Error("Invalid SPAKE2+ key share");
   }

   // Will throw if not on the curve
   const EC_AffinePoint x(m_params.group(), peer_message);

   const auto& w0 = m_record.m_w0;

   const auto y = EC_Scalar::random(m_params.group(), rng);
   const auto g = EC_AffinePoint::generator(m_params.group());

   // RFC 9383 Section 3.3: Y = y*P + w0*N
   const auto share_v_pt = EC_AffinePoint::mul_px_qy(g, y, m_params.spake2p_n(), w0, rng);
   if(!share_v_pt) {
      throw Internal_Error("Computed the identity element during SPAKE2+ key exchange");
   }
   const auto share_v = share_v_pt->serialize_uncompressed();

   // RFC 9383 Section 3.3: Z = h*y*(X - w0*M), V = h*y*L
   const auto z = EC_AffinePoint::mul_px_qy(x, y, m_params.spake2p_m(), (y * w0).negate(), rng);
   if(!z) {
      throw Decoding_Error("Invalid SPAKE2+ key share");
   }
   const auto v = m_record.m_l.mul(y, rng);

   auto keys = spake2p_key_schedule(m_params, m_context, m_prover_id, m_verifier_id, peer_message, share_v, *z, v, w0);

   m_shared_secret = std::move(keys.shared_key);
   m_expected_confirmation = std::move(keys.confirm_p);
   m_state = State::Responded;

   return concat<std::vector<uint8_t>>(share_v, keys.confirm_v);
}

void VerifierContext::verify_confirmation(std::span<const uint8_t> confirmation) {
   BOTAN_STATE_CHECK(m_state == State::Responded);

   if(!constant_time_compare(m_expected_confirmation, confirmation)) {
      m_expected_confirmation.clear();
      m_shared_secret.clear();
      m_state = State::Failed;
      throw Invalid_Authentication_Tag("SPAKE2+ key confirmation failed");
   }

   m_expected_confirmation.clear();
   m_state = State::Complete;
}

void VerifierContext::skip_confirmation() {
   BOTAN_STATE_CHECK(m_state == State::Responded);

   m_expected_confirmation.clear();
   m_state = State::Complete;
}

secure_vector<uint8_t> VerifierContext::shared_secret() const {
   BOTAN_STATE_CHECK(m_state == State::Complete);
   return m_shared_secret;
}

}  // namespace Botan::SPAKE2p
