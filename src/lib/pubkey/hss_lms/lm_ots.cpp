/**
 * LM-OTS - Leighton-Micali One-Time Signatures
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, Philippe Lieser - Rohde & Schwarz Cybersecurity GmbH
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/lm_ots.h>

#include <botan/exceptn.h>
#include <botan/strong_type.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/buffer_slicer.h>
#include <botan/internal/buffer_stuffer.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/hash_engine.h>
#include <botan/internal/hss_lms_utils.h>
#include <botan/internal/int_utils.h>

namespace Botan {

namespace {
constexpr uint16_t D_PBLC = 0x8080;
constexpr uint16_t D_MESG = 0x8181;
/// For derivation of C as in https://github.com/cisco/hash-sigs
constexpr uint16_t C_INDEX = 0xFFFD;

/**
 * Steps many hash chains at once, computing for each selected lane
 * Hash(identifier || u32str(q) || u16str(i) || u8str(j) || inputs[lane])
 *
 * The lanes cover the p chains of one or more consecutive LM-OTS
 * instances, instance-major (all chains of first_q, then those of
 * first_q + 1, ...).
 */
class Batch_Chain_Generator {
   public:
      Batch_Chain_Generator(
         Hash_Engine& engine, const LMS_Identifier& identifier, LMS_Tree_Node_Idx first_q, size_t q_count, uint16_t p) :
            m_engine(engine),
            m_prefix_len(identifier.size() + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint8_t)),
            m_prefixes(q_count * p * m_prefix_len) {
         for(size_t lane = 0; lane != q_count * p; ++lane) {
            BufferStuffer prefix(chain_prefix(lane));
            prefix.append(identifier);
            prefix.append(store_be(LMS_Tree_Node_Idx(first_q.get() + static_cast<uint32_t>(lane / p))));
            prefix.append(store_be(static_cast<uint16_t>(lane % p)));
            prefix.next(1)[0] = 0;
         }
      }

      Batch_Chain_Generator(Hash_Engine& engine, const LMS_Identifier& identifier, LMS_Tree_Node_Idx q, uint16_t p) :
            Batch_Chain_Generator(engine, identifier, q, 1, p) {}

      void process(std::span<const uint16_t> lanes,
                   uint8_t j,
                   std::span<std::span<uint8_t>> outputs,
                   std::span<std::span<const uint8_t>> inputs) {
         m_prefix_spans.resize(lanes.size());
         for(size_t c = 0; c != lanes.size(); ++c) {
            const auto prefix = chain_prefix(lanes[c]);
            prefix[m_prefix_len - 1] = j;
            m_prefix_spans[c] = prefix;
         }
         m_engine.batch_hash(outputs, m_prefix_spans, inputs);
      }

   private:
      std::span<uint8_t> chain_prefix(size_t lane) {
         return std::span(m_prefixes).subspan(lane * m_prefix_len, m_prefix_len);
      }

      Hash_Engine& m_engine;
      size_t m_prefix_len;
      std::vector<uint8_t> m_prefixes;
      std::vector<std::span<const uint8_t>> m_prefix_spans;
};

// RFC 8554 3.1.1
uint8_t byte(std::span<const uint8_t> S, uint32_t i) {
   BOTAN_ARG_CHECK(i < S.size(), "Index out of range");
   return S[i];
}

// RFC 8554 3.1.3
uint8_t coef(std::span<const uint8_t> S, uint32_t i, const LMOTS_Params& params) {
   const uint8_t w_bit_mask = params.coef_max();
   const uint8_t coef_byte = byte(S, (i * params.w()) / 8);
   const uint8_t shift = 8 - (params.w() * (i % (8 / params.w())) + params.w());

   return w_bit_mask & (coef_byte >> shift);
}

// RFC 8554 4.4
uint16_t checksum(const LMOTS_Params& params, std::span<const uint8_t> S) {
   size_t sum = 0;
   for(uint32_t i = 0; i < (params.n() * 8 / params.w()); ++i) {
      sum += params.coef_max() - coef(S, i, params);
   }
   return checked_cast_to<uint16_t>(sum << params.ls());
}

std::vector<uint8_t> gen_Q_with_cksm(const LMOTS_Params& params,
                                     const LMS_Identifier& identifier,
                                     const LMS_Tree_Node_Idx& q,
                                     std::span<const uint8_t> C,
                                     const LMS_Message& msg) {
   std::vector<uint8_t> Q_with_cksm(params.n() + sizeof(uint16_t));
   BufferStuffer qwc_stuffer(Q_with_cksm);
   const auto hash = params.hash();
   hash->update(identifier);
   hash->update(store_be(q));
   hash->update(store_be(D_MESG));
   hash->update(C);
   hash->update(msg);
   auto Q_span = qwc_stuffer.next(params.n());
   hash->final(Q_span);

   qwc_stuffer.append(store_be(checksum(params, Q_span)));

   return Q_with_cksm;
}

}  // namespace

std::unique_ptr<HashFunction> LMOTS_Params::hash() const {
   return HashFunction::create_or_throw(hash_name());
}

LMOTS_Params LMOTS_Params::create_or_throw(LMOTS_Algorithm_Type type) {
   auto [hash_name, w] = [](const LMOTS_Algorithm_Type& lmots_type) -> std::pair<std::string_view, uint8_t> {
      switch(lmots_type) {
         case LMOTS_Algorithm_Type::SHA256_N32_W1:
            return {"SHA-256", static_cast<uint8_t>(1)};
         case LMOTS_Algorithm_Type::SHA256_N32_W2:
            return {"SHA-256", static_cast<uint8_t>(2)};
         case LMOTS_Algorithm_Type::SHA256_N32_W4:
            return {"SHA-256", static_cast<uint8_t>(4)};
         case LMOTS_Algorithm_Type::SHA256_N32_W8:
            return {"SHA-256", static_cast<uint8_t>(8)};
         case LMOTS_Algorithm_Type::SHA256_N24_W1:
            return {"Truncated(SHA-256,192)", static_cast<uint8_t>(1)};
         case LMOTS_Algorithm_Type::SHA256_N24_W2:
            return {"Truncated(SHA-256,192)", static_cast<uint8_t>(2)};
         case LMOTS_Algorithm_Type::SHA256_N24_W4:
            return {"Truncated(SHA-256,192)", static_cast<uint8_t>(4)};
         case LMOTS_Algorithm_Type::SHA256_N24_W8:
            return {"Truncated(SHA-256,192)", static_cast<uint8_t>(8)};
         case LMOTS_Algorithm_Type::SHAKE_N32_W1:
            return {"SHAKE-256(256)", static_cast<uint8_t>(1)};
         case LMOTS_Algorithm_Type::SHAKE_N32_W2:
            return {"SHAKE-256(256)", static_cast<uint8_t>(2)};
         case LMOTS_Algorithm_Type::SHAKE_N32_W4:
            return {"SHAKE-256(256)", static_cast<uint8_t>(4)};
         case LMOTS_Algorithm_Type::SHAKE_N32_W8:
            return {"SHAKE-256(256)", static_cast<uint8_t>(8)};
         case LMOTS_Algorithm_Type::SHAKE_N24_W1:
            return {"SHAKE-256(192)", static_cast<uint8_t>(1)};
         case LMOTS_Algorithm_Type::SHAKE_N24_W2:
            return {"SHAKE-256(192)", static_cast<uint8_t>(2)};
         case LMOTS_Algorithm_Type::SHAKE_N24_W4:
            return {"SHAKE-256(192)", static_cast<uint8_t>(4)};
         case LMOTS_Algorithm_Type::SHAKE_N24_W8:
            return {"SHAKE-256(192)", static_cast<uint8_t>(8)};
         case LMOTS_Algorithm_Type::RESERVED:
            throw Decoding_Error("Unsupported LMS algorithm type");
      }
      throw Decoding_Error("Unsupported LMS algorithm type");
   }(type);

   return LMOTS_Params(type, hash_name, w);
}

LMOTS_Params LMOTS_Params::create_or_throw(std::string_view hash_name, uint8_t w) {
   if(w != 1 && w != 2 && w != 4 && w != 8) {
      throw Decoding_Error("Invalid Winternitz parameter");
   }
   const LMOTS_Algorithm_Type type = [](std::string_view hash, uint8_t w_p) -> LMOTS_Algorithm_Type {
      if(hash == "SHA-256") {
         switch(w_p) {
            case 1:
               return LMOTS_Algorithm_Type::SHA256_N32_W1;
            case 2:
               return LMOTS_Algorithm_Type::SHA256_N32_W2;
            case 4:
               return LMOTS_Algorithm_Type::SHA256_N32_W4;
            case 8:
               return LMOTS_Algorithm_Type::SHA256_N32_W8;
            default:
               throw Decoding_Error("Unsupported Winternitz parameter");
         }
      }
      if(hash == "Truncated(SHA-256,192)") {
         switch(w_p) {
            case 1:
               return LMOTS_Algorithm_Type::SHA256_N24_W1;
            case 2:
               return LMOTS_Algorithm_Type::SHA256_N24_W2;
            case 4:
               return LMOTS_Algorithm_Type::SHA256_N24_W4;
            case 8:
               return LMOTS_Algorithm_Type::SHA256_N24_W8;
            default:
               throw Decoding_Error("Unsupported Winternitz parameter");
         }
      }
      if(hash == "SHAKE-256(256)") {
         switch(w_p) {
            case 1:
               return LMOTS_Algorithm_Type::SHAKE_N32_W1;
            case 2:
               return LMOTS_Algorithm_Type::SHAKE_N32_W2;
            case 4:
               return LMOTS_Algorithm_Type::SHAKE_N32_W4;
            case 8:
               return LMOTS_Algorithm_Type::SHAKE_N32_W8;
            default:
               throw Decoding_Error("Unsupported Winternitz parameter");
         }
      }
      if(hash == "SHAKE-256(192)") {
         switch(w_p) {
            case 1:
               return LMOTS_Algorithm_Type::SHAKE_N24_W1;
            case 2:
               return LMOTS_Algorithm_Type::SHAKE_N24_W2;
            case 4:
               return LMOTS_Algorithm_Type::SHAKE_N24_W4;
            case 8:
               return LMOTS_Algorithm_Type::SHAKE_N24_W8;
            default:
               throw Decoding_Error("Unsupported Winternitz parameter");
         }
      }
      throw Decoding_Error("Unsupported hash function");
   }(hash_name, w);

   return LMOTS_Params(type, hash_name, w);
}

LMOTS_Params::LMOTS_Params(LMOTS_Algorithm_Type algorithm_type, std::string_view hash_name, uint8_t w) :
      m_algorithm_type(algorithm_type), m_w(w), m_hash_name(hash_name) {
   const auto hash = HashFunction::create_or_throw(m_hash_name);
   m_n = hash->output_length();
   // RFC 8553 Appendix B - Parameter Computation
   auto u = ceil_division<size_t>(8 * m_n, m_w);                         // ceil(8*n/w)
   auto v = ceil_division<size_t>(high_bit(((1 << m_w) - 1) * u), m_w);  // ceil((floor(lg[(2^w - 1) * u]) + 1) / w)
   m_ls = checked_cast_to<uint8_t>(16 - (v * w));
   m_p = checked_cast_to<uint16_t>(u + v);
}

LMOTS_Signature::LMOTS_Signature(LMOTS_Algorithm_Type lmots_type,
                                 std::vector<uint8_t> C,
                                 std::vector<uint8_t> y_buffer) :
      m_algorithm_type(lmots_type), m_C(std::move(C)), m_y_buffer(std::move(y_buffer)) {
   const LMOTS_Params params = LMOTS_Params::create_or_throw(m_algorithm_type);

   BufferSlicer y_slicer(m_y_buffer);
   for(uint16_t i = 0; i < params.p(); ++i) {
      m_y.push_back(y_slicer.take<LMOTS_Node>(params.n()));
   }
   BOTAN_ASSERT_NOMSG(y_slicer.empty());
}

LMOTS_Signature LMOTS_Signature::from_bytes_or_throw(BufferSlicer& slicer) {
   const size_t total_remaining_bytes = slicer.remaining();
   // Alg. 6a. 1. (last 4 bytes) / Alg. 4b. 1.
   if(total_remaining_bytes < sizeof(LMOTS_Algorithm_Type)) {
      throw Decoding_Error("Too few signature bytes while parsing LMOTS signature.");
   }
   // Alg. 6a. 2.b. / Alg. 4b. 2.a.
   auto algorithm_type = load_be<LMOTS_Algorithm_Type>(slicer.take<sizeof(LMOTS_Algorithm_Type)>());

   // Alg. 6a. 2.d. / Alg. 4b. 2.c.
   const LMOTS_Params params = LMOTS_Params::create_or_throw(algorithm_type);

   if(total_remaining_bytes < size(params)) {
      throw Decoding_Error("Too few signature bytes while parsing LMOTS signature.");
   }

   // Alg. 4b. 2.d.
   auto C = slicer.copy_as_vector(params.n());
   // Alg. 4b. 2.e.
   auto m_y_buffer = slicer.copy_as_vector(params.p() * params.n());

   return LMOTS_Signature(algorithm_type, std::move(C), std::move(m_y_buffer));
}

LMOTS_Private_Key::LMOTS_Private_Key(const LMOTS_Params& params,
                                     const LMS_Identifier& identifier,
                                     LMS_Tree_Node_Idx q,
                                     const LMS_Seed& seed) :
      LMOTS_Private_Key(params, identifier, q, seed, *Hash_Engine::create_or_throw(params.hash_name())) {}

LMOTS_Private_Key::LMOTS_Private_Key(const LMOTS_Params& params,
                                     const LMS_Identifier& identifier,
                                     LMS_Tree_Node_Idx q,
                                     const LMS_Seed& seed,
                                     Hash_Engine& engine) :
      OTS_Instance(params, identifier, q), m_seed(seed) {
   const uint16_t p = params.p();

   m_ots_sk.reserve(p);
   std::vector<uint16_t> chains(p);
   std::vector<std::span<uint8_t>> outputs(p);
   std::vector<std::span<const uint8_t>> inputs(p);
   for(uint16_t i = 0; i < p; ++i) {
      m_ots_sk.emplace_back(params.n());
      chains[i] = i;
      outputs[i] = std::span<uint8_t>(m_ots_sk.back().get());
      inputs[i] = std::span<const uint8_t>(seed.get());
   }

   Batch_Chain_Generator chain_gen(engine, identifier, q, p);
   chain_gen.process(chains, 0xff, outputs, inputs);
}

void LMOTS_Private_Key::sign(StrongSpan<LMOTS_Signature_Bytes> out_sig, const LMS_Message& msg) const {
   BOTAN_ARG_CHECK(out_sig.size() == LMOTS_Signature::size(params()), "Invalid output buffer size");
   BufferStuffer sig_stuffer(out_sig);
   const auto hash = params().hash();
   sig_stuffer.append(store_be(params().algorithm_type()));
   const auto C = sig_stuffer.next(params().n());

   // Since we do not store the signatures of the lms trees in the HSS sk,
   // we need deterministic signatures to avoid reusing a OTS key to generate multiple signatures.
   // See also: https://github.com/cisco/hash-sigs/blob/b0631b8891295bf2929e68761205337b7c031726/lm_ots_sign.c#L110-L115
   derive_random_C(C, *hash);
   CT::unpoison(C);  // contained in signature

   const auto Q_with_cksm = gen_Q_with_cksm(params(), identifier(), q(), C, msg);

   const uint16_t p = params().p();
   const size_t n = params().n();
   const auto y = sig_stuffer.next(p * n);
   BOTAN_ASSERT_NOMSG(sig_stuffer.full());

   std::vector<uint8_t> a(p);
   for(uint16_t i = 0; i < p; ++i) {
      a[i] = coef(Q_with_cksm, i, params());
      copy_mem(y.subspan(i * n, n), chain_input(i));
   }

   const auto engine = Hash_Engine::create_or_throw(params().hash_name());
   Batch_Chain_Generator chain_gen(*engine, identifier(), q(), p);

   std::vector<uint16_t> active;
   std::vector<std::span<uint8_t>> outputs;
   std::vector<std::span<const uint8_t>> inputs;
   active.reserve(p);
   outputs.reserve(p);
   inputs.reserve(p);

   // Chain i takes a[i] steps in total; step all unfinished chains together
   for(uint8_t j = 0;; ++j) {
      active.clear();
      outputs.clear();
      inputs.clear();
      for(uint16_t i = 0; i < p; ++i) {
         if(j < a[i]) {
            active.push_back(i);
            const auto node = y.subspan(i * n, n);
            outputs.push_back(node);
            inputs.push_back(node);
         }
      }
      if(active.empty()) {
         break;
      }
      chain_gen.process(active, j, outputs, inputs);
   }
}

void LMOTS_Private_Key::derive_random_C(std::span<uint8_t> out, HashFunction& hash) const {
   PseudorandomKeyGeneration gen(identifier());

   gen.set_q(q().get());
   gen.set_i(C_INDEX);
   gen.set_j(0xff);

   gen.gen(out, hash, m_seed);
}

LMOTS_Public_Key::LMOTS_Public_Key(const LMOTS_Private_Key& lmots_sk) :
      LMOTS_Public_Key(lmots_sk, *Hash_Engine::create_or_throw(lmots_sk.params().hash_name())) {}

LMOTS_Public_Key::LMOTS_Public_Key(const LMOTS_Private_Key& lmots_sk, Hash_Engine& engine) :
      /* NOLINT(*-slicing) */ OTS_Instance(lmots_sk) {
   const uint16_t p = lmots_sk.params().p();
   const size_t n = lmots_sk.params().n();

   // Walk all chains to the top in lock-step
   secure_vector<uint8_t> nodes(p * n);
   std::vector<uint16_t> chains(p);
   std::vector<std::span<uint8_t>> outputs(p);
   std::vector<std::span<const uint8_t>> inputs(p);
   for(uint16_t i = 0; i < p; ++i) {
      chains[i] = i;
      const auto node = std::span(nodes).subspan(i * n, n);
      copy_mem(node, lmots_sk.chain_input(i));
      outputs[i] = node;
      inputs[i] = node;
   }

   Batch_Chain_Generator chain_gen(engine, lmots_sk.identifier(), lmots_sk.q(), p);
   for(uint8_t j = 0; j < lmots_sk.params().coef_max(); ++j) {
      chain_gen.process(chains, j, outputs, inputs);
   }

   const auto pk_hash = lmots_sk.params().hash();
   pk_hash->update(lmots_sk.identifier());
   pk_hash->update(store_be(lmots_sk.q()));
   pk_hash->update(store_be(D_PBLC));
   pk_hash->update(nodes);
   m_K = pk_hash->final<LMOTS_K>();
}

void lmots_compute_pubkeys(std::span<uint8_t> out_ks,
                           const LMOTS_Params& params,
                           const LMS_Identifier& identifier,
                           LMS_Tree_Node_Idx first_q,
                           size_t count,
                           const LMS_Seed& seed,
                           Hash_Engine& engine) {
   BOTAN_ASSERT_NOMSG(out_ks.size() == count * params.n());

   const uint16_t p = params.p();
   const size_t n = params.n();
   const size_t lanes = count * p;
   BOTAN_ASSERT_NOMSG(lanes <= 0xFFFF);

   secure_vector<uint8_t> nodes(lanes * n);

   std::vector<uint16_t> lane_ids(lanes);
   std::vector<std::span<uint8_t>> outputs(lanes);
   std::vector<std::span<const uint8_t>> inputs(lanes);
   for(size_t l = 0; l != lanes; ++l) {
      lane_ids[l] = static_cast<uint16_t>(l);
      outputs[l] = std::span(nodes).subspan(l * n, n);
      inputs[l] = std::span<const uint8_t>(seed.get());
   }

   Batch_Chain_Generator chain_gen(engine, identifier, first_q, count, p);

   // Derive the secret chain inputs (x[] in RFC 8554 4.2)
   chain_gen.process(lane_ids, 0xff, outputs, inputs);

   // Walk all chains of all instances to the top in lock-step
   for(size_t l = 0; l != lanes; ++l) {
      inputs[l] = outputs[l];
   }
   for(uint8_t j = 0; j < params.coef_max(); ++j) {
      chain_gen.process(lane_ids, j, outputs, inputs);
   }

   // Compute each instance's K over its chain ends (RFC 8554 4.3)
   const size_t k_prefix_len = identifier.size() + sizeof(uint32_t) + sizeof(uint16_t);
   std::vector<uint8_t> k_prefixes(count * k_prefix_len);
   std::vector<std::span<uint8_t>> k_outs(count);
   std::vector<std::span<const uint8_t>> k_prefix_spans(count);
   std::vector<std::span<const uint8_t>> k_nodes(count);
   for(size_t i = 0; i != count; ++i) {
      const auto prefix_span = std::span(k_prefixes).subspan(i * k_prefix_len, k_prefix_len);
      BufferStuffer prefix(prefix_span);
      prefix.append(identifier);
      prefix.append(store_be(LMS_Tree_Node_Idx(first_q.get() + static_cast<uint32_t>(i))));
      prefix.append(store_be(D_PBLC));
      k_prefix_spans[i] = prefix_span;
      k_outs[i] = out_ks.subspan(i * n, n);
      k_nodes[i] = std::span(nodes).subspan(i * p * n, p * n);
   }
   engine.batch_hash(k_outs, k_prefix_spans, k_nodes);
}

LMOTS_K lmots_compute_pubkey_from_sig(const LMOTS_Signature& sig,
                                      const LMS_Message& msg,
                                      const LMS_Identifier& identifier,
                                      LMS_Tree_Node_Idx q) {
   auto params = LMOTS_Params::create_or_throw(sig.algorithm_type());

   // Alg. 4b 3.

   const auto Q_with_cksm = gen_Q_with_cksm(params, identifier, q, sig.C(), msg);

   const uint16_t p = params.p();
   const size_t n = params.n();

   secure_vector<uint8_t> nodes(p * n);
   std::vector<uint8_t> a(p);
   for(uint16_t i = 0; i < p; ++i) {
      a[i] = coef(Q_with_cksm, i, params);
      copy_mem(std::span(nodes).subspan(i * n, n), sig.y(i));
   }

   const auto engine = Hash_Engine::create_or_throw(params.hash_name());
   Batch_Chain_Generator chain_gen(*engine, identifier, q, p);

   std::vector<uint16_t> active;
   std::vector<std::span<uint8_t>> outputs;
   std::vector<std::span<const uint8_t>> inputs;
   active.reserve(p);
   outputs.reserve(p);
   inputs.reserve(p);

   // Chain i continues from position a[i] up to the top
   for(uint8_t j = 0; j < params.coef_max(); ++j) {
      active.clear();
      outputs.clear();
      inputs.clear();
      for(uint16_t i = 0; i < p; ++i) {
         if(a[i] <= j) {
            active.push_back(i);
            const auto node = std::span(nodes).subspan(i * n, n);
            outputs.push_back(node);
            inputs.push_back(node);
         }
      }
      if(!active.empty()) {
         chain_gen.process(active, j, outputs, inputs);
      }
   }

   // Prefill the final hash object
   const auto pk_hash = params.hash();
   pk_hash->update(identifier);
   pk_hash->update(store_be(q));
   pk_hash->update(store_be(D_PBLC));
   pk_hash->update(nodes);
   // Alg. 4b 4.
   return pk_hash->final<LMOTS_K>();
}

}  // namespace Botan
