/*
* BLS signatures built from the low level BLS12-381 interface.
*
* This implements the scheme of draft-irtf-cfrg-bls-signature in the
* minimal-pubkey-size setting (public keys in G1, signatures in G2),
* specifically the "basic" ciphersuite
* BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_.
*
* The basic scheme is only safe for aggregation if all messages in an
* aggregate are distinct; see section 3.1 of the draft. The
* message-augmentation and proof-of-possession variants build on the
* same operations shown here.
*/

#include <botan/auto_rng.h>
#include <botan/bls12_381.h>

#include <iostream>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace {

using namespace Botan::BLS12_381;

const std::string_view BLS_SIG_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

std::span<const uint8_t> as_bytes(std::string_view s) {
   return {reinterpret_cast<const uint8_t*>(s.data()), s.size()};
}

G2Projective hash_message(std::string_view msg) {
   return G2Projective::hash_to_curve_ro(as_bytes(msg), as_bytes(BLS_SIG_DST));
}

class BlsPrivateKey {
   public:
      /*
      * Generate a signing key.
      *
      * Note that section 2.3 of the draft specifies a deterministic
      * HKDF based derivation from a seed; if interoperable key
      * derivation matters for your application, implement KeyGen with
      * Botan's HKDF. Here fresh randomness is used directly.
      */
      static BlsPrivateKey generate(Botan::RandomNumberGenerator& rng) {
         for(;;) {
            std::array<uint8_t, 64> seed{};
            rng.randomize(seed);
            const auto sk = Scalar::from_bytes_wide(seed);

            // The secret key must be nonzero (probability 2^-255)
            if(sk.serialize() != Scalar::zero().serialize()) {
               return BlsPrivateKey(sk);
            }
         }
      }

      // SkToPk: the public key is sk*g1, serialized to 48 bytes
      std::array<uint8_t, G1Affine::BYTES> public_key() const {
         return G1Projective::generator().mul(m_sk).to_affine().serialize();
      }

      // CoreSign: the signature is sk*H(msg), serialized to 96 bytes
      std::array<uint8_t, G2Affine::BYTES> sign(std::string_view msg) const {
         return hash_message(msg).mul(m_sk).to_affine().serialize();
      }

   private:
      explicit BlsPrivateKey(const Scalar& sk) : m_sk(sk) {}

      Scalar m_sk;
};

/*
* CoreVerify: check that e(pk, H(msg)) == e(g1, sig).
*
* Deserialization rejects any point outside the prime order subgroup,
* which the scheme requires. The pairing equation is rearranged as
* e(pk, H(msg)) * e(-g1, sig) == 1 so that a single product of pairings
* (with its one shared final exponentiation) suffices.
*/
bool bls_verify(std::span<const uint8_t> pk_bytes, std::string_view msg, std::span<const uint8_t> sig_bytes) {
   const auto pk = G1Affine::deserialize(pk_bytes);
   const auto sig = G2Affine::deserialize(sig_bytes);
   if(!pk || !sig || pk->is_identity()) {
      return false;
   }

   const auto neg_g1 = G1Projective::generator().negate().to_affine();

   const std::vector<G1Affine> ps{*pk, neg_g1};
   const std::vector<G2Affine> qs{hash_message(msg).to_affine(), *sig};
   return Gt::multi_pairing(ps, qs).is_identity();
}

// Aggregate: signatures combine by group addition in G2
std::optional<std::array<uint8_t, G2Affine::BYTES>> bls_aggregate(
   std::span<const std::array<uint8_t, G2Affine::BYTES>> sigs) {
   auto agg = G2Projective::identity();
   for(const auto& sig_bytes : sigs) {
      const auto sig = G2Affine::deserialize(sig_bytes);
      if(!sig) {
         return std::nullopt;
      }
      agg = agg.add_mixed(*sig);
   }
   return agg.to_affine().serialize();
}

/*
* CoreAggregateVerify: check e(pk_1, H(msg_1)) * ... * e(pk_n, H(msg_n)) == e(g1, sig)
* via one product of n+1 pairings.
*
* Warning: in the basic scheme the messages MUST be pairwise distinct,
* otherwise the aggregate is forgeable by a rogue key attack. This
* example does not check distinctness.
*/
bool bls_aggregate_verify(std::span<const std::vector<uint8_t>> pks,
                          std::span<const std::string_view> msgs,
                          std::span<const uint8_t> agg_sig_bytes) {
   if(pks.size() != msgs.size() || pks.empty()) {
      return false;
   }

   const auto agg_sig = G2Affine::deserialize(agg_sig_bytes);
   if(!agg_sig) {
      return false;
   }

   std::vector<G1Affine> ps;
   std::vector<G2Projective> hashed;
   for(size_t i = 0; i != pks.size(); ++i) {
      const auto pk = G1Affine::deserialize(pks[i]);
      if(!pk || pk->is_identity()) {
         return false;
      }
      ps.push_back(*pk);
      hashed.push_back(hash_message(msgs[i]));
   }

   ps.push_back(G1Projective::generator().negate().to_affine());

   // A single shared inversion converts all the hashed points at once
   auto qs = G2Projective::to_affine_batch(hashed);
   qs.push_back(*agg_sig);

   return Gt::multi_pairing(ps, qs).is_identity();
}

}  // namespace

int main() {
   Botan::AutoSeeded_RNG rng;

   bool all_ok = true;
   auto check = [&](const char* what, bool ok, bool expected) {
      std::cout << what << ": " << (ok ? "valid" : "invalid") << "\n";
      all_ok = all_ok && (ok == expected);
   };

   // Single signer
   const auto key = BlsPrivateKey::generate(rng);
   const auto pk = key.public_key();

   const std::string_view message = "This is a tasty burger!";
   const auto sig = key.sign(message);

   check("Signature", bls_verify(pk, message, sig), true);
   check("Signature on modified message", bls_verify(pk, "This is a nasty burger!", sig), false);

   // Aggregation: three signers, three (distinct!) messages, one signature
   const std::vector<std::string_view> messages{
      "message to the first signer", "message to the second signer", "message to the third signer"};

   std::vector<std::vector<uint8_t>> pks;
   std::vector<std::array<uint8_t, G2Affine::BYTES>> sigs;
   for(const auto msg : messages) {
      const auto k = BlsPrivateKey::generate(rng);
      const auto k_pk = k.public_key();
      pks.emplace_back(k_pk.begin(), k_pk.end());
      sigs.push_back(k.sign(msg));
   }

   const auto agg_sig = bls_aggregate(sigs);
   if(!agg_sig) {
      std::cout << "Aggregation failed\n";
      return 1;
   }

   check("Aggregate signature", bls_aggregate_verify(pks, messages, *agg_sig), true);

   auto swapped = messages;
   std::swap(swapped[0], swapped[1]);
   check("Aggregate with swapped messages", bls_aggregate_verify(pks, swapped, *agg_sig), false);

   return all_ok ? 0 : 1;
}
