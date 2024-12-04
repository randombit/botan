/**
 * LMS - Leighton-Micali Hash-Based Signatures (RFC 8554)
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, Philippe Lieser - Rohde & Schwarz Cybersecurity GmbH
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/lms.h>

#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/tree_hash.h>

namespace Botan {
namespace {

/**
 * @brief Domain-separation parameter when computing the hash of the leaf of an LMS tree.
 */
constexpr uint16_t D_LEAF = 0x8282;

/**
 * @brief Domain-separation parameter when computing the hash of an interior node of an LMS tree.
 */
constexpr uint16_t D_INTR = 0x8383;

/// Index of the layer in a tree starting with 0 for the bottom level to the root layer
using LMS_TreeLayerIndex = Strong<uint32_t, struct LMS_TreeLayerIndex_, EnableArithmeticWithPlainNumber>;

class TreeAddress final {
   public:
      explicit TreeAddress(uint32_t total_tree_height) : m_h(total_tree_height), m_r(0) {
         BOTAN_ARG_CHECK(total_tree_height > 0 && total_tree_height < 32, "Invalid tree height");
      }

      TreeAddress& set_address(LMS_TreeLayerIndex tree_layer, LMS_Tree_Node_Idx tree_index) {
         BOTAN_ARG_CHECK(tree_index.get() < (1 << m_h), "Invalid tree index");
         BOTAN_ARG_CHECK(tree_layer.get() <= m_h, "Invalid tree index");
         m_r = (1 << (m_h - tree_layer)).get() + tree_index.get();
         return *this;
      }

      uint32_t r() const { return m_r; }

      bool is_leaf() const { return m_r >= (1 << m_h); }

      LMS_Tree_Node_Idx q() const {
         BOTAN_STATE_CHECK(is_leaf());
         return LMS_Tree_Node_Idx(m_r - (1 << m_h.get()));
      }

   private:
      LMS_TreeLayerIndex m_h;
      uint32_t m_r;
};

auto get_hash_pair_func_for_identifier(const LMS_Params& lms_params, LMS_Identifier identifier) {
   return [hash = lms_params.hash(), I = std::move(identifier)](StrongSpan<LMS_Tree_Node> out,
                                                                const TreeAddress& address,
                                                                StrongSpan<const LMS_Tree_Node> left,
                                                                StrongSpan<const LMS_Tree_Node> right) {
      hash->update(I);
      hash->update(store_be(address.r()));
      hash->update(store_be(D_INTR));
      hash->update(left);
      hash->update(right);
      hash->final(out);
   };
}

void lms_gen_leaf(StrongSpan<LMS_Tree_Node> out,
                  const LMOTS_Public_Key& lmots_pk,
                  const TreeAddress& tree_address,
                  HashFunction& hash) {
   hash.update(lmots_pk.identifier());
   hash.update(store_be(tree_address.r()));
   hash.update(store_be(D_LEAF));
   hash.update(lmots_pk.K());
   hash.final(out);
}

auto lms_gen_leaf_func(const LMS_PrivateKey& lms_sk) {
   return [hash = lms_sk.lms_params().hash(), lms_sk](StrongSpan<LMS_Tree_Node> out, const TreeAddress& tree_address) {
      auto lmots_sk = LMOTS_Private_Key(lms_sk.lmots_params(), lms_sk.identifier(), tree_address.q(), lms_sk.seed());
      auto lmots_pk = LMOTS_Public_Key(lmots_sk);
      lms_gen_leaf(out, lmots_pk, tree_address, *hash);
   };
}

void lms_treehash(StrongSpan<LMS_Tree_Node> out_root,
                  std::optional<StrongSpan<LMS_AuthenticationPath>> out_auth_path,
                  std::optional<LMS_Tree_Node_Idx> leaf_idx,
                  const LMS_PrivateKey& lms_sk) {
   auto hash_pair_func = get_hash_pair_func_for_identifier(lms_sk.lms_params(), lms_sk.identifier());
   auto gen_leaf = lms_gen_leaf_func(lms_sk);
   TreeAddress lms_tree_address(lms_sk.lms_params().h());

   treehash(out_root,
            out_auth_path,
            leaf_idx,
            lms_sk.lms_params().m(),
            LMS_TreeLayerIndex(lms_sk.lms_params().h()),
            0,
            std::move(hash_pair_func),
            std::move(gen_leaf),
            lms_tree_address);
}

}  // namespace

LMS_Params LMS_Params::create_or_throw(LMS_Algorithm_Type type) {
   auto [hash_name, height] = [](const LMS_Algorithm_Type& lms_type) -> std::pair<std::string_view, uint8_t> {
      switch(lms_type) {
         case LMS_Algorithm_Type::SHA256_M32_H5:
            return {"SHA-256", static_cast<uint8_t>(5)};
         case LMS_Algorithm_Type::SHA256_M32_H10:
            return {"SHA-256", static_cast<uint8_t>(10)};
         case LMS_Algorithm_Type::SHA256_M32_H15:
            return {"SHA-256", static_cast<uint8_t>(15)};
         case LMS_Algorithm_Type::SHA256_M32_H20:
            return {"SHA-256", static_cast<uint8_t>(20)};
         case LMS_Algorithm_Type::SHA256_M32_H25:
            return {"SHA-256", static_cast<uint8_t>(25)};
         case LMS_Algorithm_Type::SHA256_M24_H5:
            return {"Truncated(SHA-256,192)", static_cast<uint8_t>(5)};
         case LMS_Algorithm_Type::SHA256_M24_H10:
            return {"Truncated(SHA-256,192)", static_cast<uint8_t>(10)};
         case LMS_Algorithm_Type::SHA256_M24_H15:
            return {"Truncated(SHA-256,192)", static_cast<uint8_t>(15)};
         case LMS_Algorithm_Type::SHA256_M24_H20:
            return {"Truncated(SHA-256,192)", static_cast<uint8_t>(20)};
         case LMS_Algorithm_Type::SHA256_M24_H25:
            return {"Truncated(SHA-256,192)", static_cast<uint8_t>(25)};
         case LMS_Algorithm_Type::SHAKE_M32_H5:
            return {"SHAKE-256(256)", static_cast<uint8_t>(5)};
         case LMS_Algorithm_Type::SHAKE_M32_H10:
            return {"SHAKE-256(256)", static_cast<uint8_t>(10)};
         case LMS_Algorithm_Type::SHAKE_M32_H15:
            return {"SHAKE-256(256)", static_cast<uint8_t>(15)};
         case LMS_Algorithm_Type::SHAKE_M32_H20:
            return {"SHAKE-256(256)", static_cast<uint8_t>(20)};
         case LMS_Algorithm_Type::SHAKE_M32_H25:
            return {"SHAKE-256(256)", static_cast<uint8_t>(25)};
         case LMS_Algorithm_Type::SHAKE_M24_H5:
            return {"SHAKE-256(192)", static_cast<uint8_t>(5)};
         case LMS_Algorithm_Type::SHAKE_M24_H10:
            return {"SHAKE-256(192)", static_cast<uint8_t>(10)};
         case LMS_Algorithm_Type::SHAKE_M24_H15:
            return {"SHAKE-256(192)", static_cast<uint8_t>(15)};
         case LMS_Algorithm_Type::SHAKE_M24_H20:
            return {"SHAKE-256(192)", static_cast<uint8_t>(20)};
         case LMS_Algorithm_Type::SHAKE_M24_H25:
            return {"SHAKE-256(192)", static_cast<uint8_t>(25)};
         default:
            throw Decoding_Error("Unsupported LMS algorithm type");
      }
   }(type);

   return LMS_Params(type, hash_name, height);
}

LMS_Params LMS_Params::create_or_throw(std::string_view hash_name, uint8_t height) {
   LMS_Algorithm_Type type = [](std::string_view hash, uint8_t h) -> LMS_Algorithm_Type {
      if(hash == "SHA-256") {
         switch(h) {
            case 5:
               return LMS_Algorithm_Type::SHA256_M32_H5;
            case 10:
               return LMS_Algorithm_Type::SHA256_M32_H10;
            case 15:
               return LMS_Algorithm_Type::SHA256_M32_H15;
            case 20:
               return LMS_Algorithm_Type::SHA256_M32_H20;
            case 25:
               return LMS_Algorithm_Type::SHA256_M32_H25;
            default:
               throw Decoding_Error("Unsupported height for hash function");
         }
      }
      if(hash == "Truncated(SHA-256,192)") {
         switch(h) {
            case 5:
               return LMS_Algorithm_Type::SHA256_M24_H5;
            case 10:
               return LMS_Algorithm_Type::SHA256_M24_H10;
            case 15:
               return LMS_Algorithm_Type::SHA256_M24_H15;
            case 20:
               return LMS_Algorithm_Type::SHA256_M24_H20;
            case 25:
               return LMS_Algorithm_Type::SHA256_M24_H25;
            default:
               throw Decoding_Error("Unsupported height for hash function");
         }
      }
      if(hash == "SHAKE-256(256)") {
         switch(h) {
            case 5:
               return LMS_Algorithm_Type::SHAKE_M32_H5;
            case 10:
               return LMS_Algorithm_Type::SHAKE_M32_H10;
            case 15:
               return LMS_Algorithm_Type::SHAKE_M32_H15;
            case 20:
               return LMS_Algorithm_Type::SHAKE_M32_H20;
            case 25:
               return LMS_Algorithm_Type::SHAKE_M32_H25;
            default:
               throw Decoding_Error("Unsupported height for hash function");
         }
      }
      if(hash == "SHAKE-256(192)") {
         switch(h) {
            case 5:
               return LMS_Algorithm_Type::SHAKE_M24_H5;
            case 10:
               return LMS_Algorithm_Type::SHAKE_M24_H10;
            case 15:
               return LMS_Algorithm_Type::SHAKE_M24_H15;
            case 20:
               return LMS_Algorithm_Type::SHAKE_M24_H20;
            case 25:
               return LMS_Algorithm_Type::SHAKE_M24_H25;
            default:
               throw Decoding_Error("Unsupported height for hash function");
         }
      }
      throw Decoding_Error("Unsupported hash function");
   }(hash_name, height);

   return LMS_Params(type, hash_name, height);
}

LMS_Params::LMS_Params(LMS_Algorithm_Type algorithm_type, std::string_view hash_name, uint8_t h) :
      m_algorithm_type(algorithm_type), m_h(h), m_hash_name(hash_name) {
   const auto hash = HashFunction::create_or_throw(m_hash_name);
   m_m = hash->output_length();
}

LMS_PublicKey LMS_PrivateKey::sign_and_get_pk(StrongSpan<LMS_Signature_Bytes> out_sig,
                                              LMS_Tree_Node_Idx q,
                                              const LMS_Message& msg) const {
   // Pre-alloc space for the signature
   BOTAN_ARG_CHECK(out_sig.size() == LMS_Signature::size(lms_params(), lmots_params()), "Invalid output buffer size");

   BufferStuffer sig_stuffer(out_sig);
   sig_stuffer.append(store_be(q));
   const LMOTS_Private_Key lmots_sk(lmots_params(), identifier(), q, seed());
   lmots_sk.sign(sig_stuffer.next<LMOTS_Signature_Bytes>(LMOTS_Signature::size(lmots_params())), msg);
   sig_stuffer.append(store_be(lms_params().algorithm_type()));
   const auto auth_path_buffer = sig_stuffer.next<LMS_AuthenticationPath>(lms_params().m() * lms_params().h());

   BOTAN_ASSERT_NOMSG(sig_stuffer.full());

   TreeAddress lms_tree_address(lms_params().h());
   LMS_Tree_Node pk_buffer(lms_params().m());
   lms_treehash(StrongSpan<LMS_Tree_Node>(pk_buffer.get()), auth_path_buffer, q, *this);

   CT::unpoison(pk_buffer);
   return LMS_PublicKey(lms_params(), lmots_params(), identifier(), std::move(pk_buffer));
}

LMS_PublicKey LMS_PublicKey::from_bytes_or_throw(BufferSlicer& slicer) {
   size_t total_remaining_bytes = slicer.remaining();
   // Alg. 6. 1. (4 bytes are sufficient until the next check)
   if(total_remaining_bytes < sizeof(LMS_Algorithm_Type)) {
      throw Decoding_Error("Too few bytes while parsing LMS public key.");
   }
   // Alg. 6. 2.a.
   auto lms_type = load_be<LMS_Algorithm_Type>(slicer.take<sizeof(LMS_Algorithm_Type)>());
   // Alg. 6. 2.c.
   auto lms_params = LMS_Params::create_or_throw(lms_type);
   // Alg. 6. 2.d.
   if(total_remaining_bytes < LMS_PublicKey::size(lms_params)) {
      throw Decoding_Error("Too few bytes while parsing LMS public key.");
   }
   // Alg. 6. 2.b.
   auto lmots_type = load_be<LMOTS_Algorithm_Type>(slicer.take<sizeof(LMOTS_Algorithm_Type)>());
   auto lmots_params = LMOTS_Params::create_or_throw(lmots_type);

   if(lms_params.hash_name() != lmots_params.hash_name()) {
      throw Decoding_Error("No support for HSS-LMS instances with multiple hash functions.");
   }

   // Alg. 6. 2.e.
   auto I = slicer.copy<LMS_Identifier>(LMS_IDENTIFIER_LEN);
   // Alg. 6. 2.f.
   auto lms_root = slicer.copy<LMS_Tree_Node>(lms_params.m());

   return LMS_PublicKey(std::move(lms_params), std::move(lmots_params), std::move(I), std::move(lms_root));
}

std::vector<uint8_t> LMS_PublicKey::to_bytes() const {
   // clang-format off
   return concat<std::vector<uint8_t>>(
      store_be(lms_params().algorithm_type()),
      store_be(lmots_params().algorithm_type()),
      identifier(),
      m_lms_root);
   // clang-format on
}

LMS_PublicKey::LMS_PublicKey(LMS_Params lms_params,
                             LMOTS_Params lmots_params,
                             LMS_Identifier I,
                             LMS_Tree_Node lms_root) :
      LMS_Instance(std::move(lms_params), std::move(lmots_params), std::move(I)), m_lms_root(std::move(lms_root)) {
   BOTAN_ARG_CHECK(identifier().size() == LMS_IDENTIFIER_LEN, "Invalid LMS identifier");
   BOTAN_ARG_CHECK(m_lms_root.size() == this->lms_params().m(), "Invalid LMS root");
}

size_t LMS_PublicKey::size(const LMS_Params& lms_params) {
   return sizeof(LMS_Algorithm_Type) + sizeof(LMOTS_Algorithm_Type) + LMS_IDENTIFIER_LEN + lms_params.m();
}

LMS_Signature LMS_Signature::from_bytes_or_throw(BufferSlicer& slicer) {
   size_t total_remaining_bytes = slicer.remaining();
   // Alg. 6a 1. (next 4 bytes are checked in LMOTS_Signature::from_bytes_or_throw)
   if(total_remaining_bytes < sizeof(LMS_Tree_Node_Idx)) {
      throw Decoding_Error("Too few signature bytes while parsing LMS signature.");
   }
   // Alg. 6a 2.a.
   auto q = load_be<LMS_Tree_Node_Idx>(slicer.take<sizeof(LMS_Tree_Node_Idx)>());

   // Alg. 6a 2.b.-e.
   auto lmots_sig = LMOTS_Signature::from_bytes_or_throw(slicer);
   LMOTS_Params lmots_params = LMOTS_Params::create_or_throw(lmots_sig.algorithm_type());

   if(slicer.remaining() < sizeof(LMS_Algorithm_Type)) {
      throw Decoding_Error("Too few signature bytes while parsing LMS signature.");
   }
   // Alg. 6a 2.f.
   auto lms_type = load_be<LMS_Algorithm_Type>(slicer.take<sizeof(LMS_Algorithm_Type)>());
   // Alg. 6a 2.h.
   LMS_Params lms_params = LMS_Params::create_or_throw(lms_type);
   // Alg. 6a 2.i. (signature is not exactly [...] bytes long)
   if(total_remaining_bytes < size(lms_params, lmots_params)) {
      throw Decoding_Error("Too few signature bytes while parsing LMS signature.");
   }

   // Alg. 6a 2.j.
   auto auth_path = slicer.copy<LMS_AuthenticationPath>(lms_params.m() * lms_params.h());

   return LMS_Signature(q, std::move(lmots_sig), lms_type, std::move(auth_path));
}

LMS_PublicKey::LMS_PublicKey(const LMS_PrivateKey& sk) : LMS_Instance(sk), m_lms_root(sk.lms_params().m()) {
   lms_treehash(StrongSpan<LMS_Tree_Node>(m_lms_root), std::nullopt, std::nullopt, sk);
}

bool LMS_PublicKey::verify_signature(const LMS_Message& msg, const LMS_Signature& sig) const {
   if(lms_root().size() != lms_params().m()) {
      // LMS public key (T[1] part) has unexpected length
      return false;
   }
   if(lms_params().algorithm_type() != sig.lms_type()) {
      // LMS algorithm type does not match with the signature's
      return false;
   }
   // Alg. 6a 2.g.
   if(lmots_params().algorithm_type() != sig.lmots_sig().algorithm_type()) {
      // LMOTS algorithm type does not match with the signature's
      return false;
   }
   // Alg. 6a 2.i.
   if(sig.q() >= (1ULL << uint64_t(lms_params().h()))) {
      return false;
   }
   // Alg 6. 3.
   std::optional<LMS_Tree_Node> Tc = lms_compute_root_from_sig(msg, sig);
   if(!Tc.has_value()) {
      return false;
   }
   // Alg 6. 4.
   return Tc.value() == lms_root();
}

std::optional<LMS_Tree_Node> LMS_PublicKey::lms_compute_root_from_sig(const LMS_Message& msg,
                                                                      const LMS_Signature& sig) const {
   // Alg. 6a 2.c, 2.g
   if(lms_params().algorithm_type() != sig.lms_type() ||
      lmots_params().algorithm_type() != sig.lmots_sig().algorithm_type()) {
      return std::nullopt;
   }
   try {
      const LMS_Params lms_params = LMS_Params::create_or_throw(sig.lms_type());
      const LMOTS_Signature& lmots_sig = sig.lmots_sig();
      const LMOTS_Params lmots_params = LMOTS_Params::create_or_throw(lmots_sig.algorithm_type());
      const LMOTS_K Kc = lmots_compute_pubkey_from_sig(lmots_sig, msg, identifier(), sig.q());
      const auto hash = lms_params.hash();

      auto hash_pair_func = get_hash_pair_func_for_identifier(lms_params, identifier());

      auto lms_address = TreeAddress(lms_params.h());
      lms_address.set_address(LMS_TreeLayerIndex(0), LMS_Tree_Node_Idx(sig.q().get()));

      LMOTS_Public_Key pk_candidate(lmots_params, identifier(), sig.q(), Kc);
      LMS_Tree_Node tmp(lms_params.m());
      lms_gen_leaf(tmp, pk_candidate, lms_address, *hash);

      LMS_Tree_Node root(lms_params.m());

      compute_root(StrongSpan<LMS_Tree_Node>(root),
                   sig.auth_path(),
                   sig.q(),
                   StrongSpan<const LMS_Tree_Node>(tmp),
                   lms_params.m(),
                   LMS_TreeLayerIndex(lms_params.h()),
                   0,
                   std::move(hash_pair_func),
                   lms_address);
      return LMS_Tree_Node(root);
   } catch(const Decoding_Error&) {
      return std::nullopt;
   }
}

size_t LMS_Signature::size(const LMS_Params& lms_params, const LMOTS_Params& lmots_params) {
   return sizeof(uint32_t) + LMOTS_Signature::size(lmots_params) + sizeof(uint32_t) + lms_params.h() * lms_params.m();
}

}  // namespace Botan
