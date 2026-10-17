/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/mp_mulx.h>

#include <botan/mem_ops.h>
#include <botan/internal/mp_core.h>

namespace Botan {

namespace {

// NOLINTBEGIN(*-macro-usage,*-no-assembler,*-const-correctness)
// clang-format off

/*
* One word of out = t + x * b: the high half of the previous product arrives
* on the overflow flag chain (ADOX) and the low half of this one on the
* carry flag chain (ADCX), so the two chains never wait on each other.
*/
#define BOTAN_MULADD_STEP(D)                   \
   "movq " D "(%[t]), %[tmp]\n\t"              \
   "adox %[carry], %[tmp]\n\t"                 \
   "mulx " D "(%[x]), %[lo], %[carry]\n\t"     \
   "adcx %[lo], %[tmp]\n\t"                    \
   "movq %[tmp], " D "(%[out])\n\t"

/*
* out[0..K) = t[0..K) + x[0..K) * b + carry for K steps, returning the carry
* out. The two flag carries left after the last step are folded into its
* product's high half, which fits since the sum is at most b.
*/
#define BOTAN_MULADD_ASM(STEPS)                                                                     \
   asm volatile("xorl %k[zero], %k[zero]\n\t"                                                       \
                STEPS                                                                               \
                "adox %[zero], %[carry]\n\t"                                                        \
                "adcx %[zero], %[carry]\n\t"                                                        \
                : [carry] "+&r"(carry), [tmp] "=&r"(tmp), [lo] "=&r"(lo), [zero] "=&r"(zero)        \
                : [out] "r"(out), [t] "r"(t), [x] "r"(x), "d"(b)                                    \
                : "cc", "memory")

#define BOTAN_MULADD_STEPS4                    \
   BOTAN_MULADD_STEP("0")                      \
   BOTAN_MULADD_STEP("8")                      \
   BOTAN_MULADD_STEP("16")                     \
   BOTAN_MULADD_STEP("24")

#define BOTAN_MULADD_STEPS8                    \
   BOTAN_MULADD_STEPS4                         \
   BOTAN_MULADD_STEP("32")                     \
   BOTAN_MULADD_STEP("40")                     \
   BOTAN_MULADD_STEP("48")                     \
   BOTAN_MULADD_STEP("56")

// out[0..8) = t[0..8) + x[0..8) * b + carry; out may be t or t - 1
BOTAN_FORCE_INLINE word muladd8(word* out, const word* t, const word* x, word b, word carry) {
   word tmp = 0;
   word lo = 0;
   word zero = 0;
   BOTAN_MULADD_ASM(BOTAN_MULADD_STEPS8);
   return carry;
}

// out[0..4) = t[0..4) + x[0..4) * b + carry; out may be t or t - 1
BOTAN_FORCE_INLINE word muladd4(word* out, const word* t, const word* x, word b, word carry) {
   word tmp = 0;
   word lo = 0;
   word zero = 0;
   BOTAN_MULADD_ASM(BOTAN_MULADD_STEPS4);
   return carry;
}

// clang-format on
// NOLINTEND(*-macro-usage,*-no-assembler,*-const-correctness)

/*
* out[0..N+2) = t[0..N+2) + x[0..N) * b + c * B^(N+1), returning the carry
* out of out[N+1]. out may be t or t - 1.
*/
BOTAN_FORCE_INLINE word monty_row(word* out, const word* t, const word* x, size_t N, word b, word c) {
   word carry = 0;
   // Advancing the pointers, rather than indexing, keeps the compiler from generating a slower loop
   for(size_t i = N / 8; i != 0; --i) {
      carry = muladd8(out, t, x, b, carry);
      out += 8;
      t += 8;
      x += 8;
   }
   if(N % 8 >= 4) {
      carry = muladd4(out, t, x, b, carry);
      out += 4;
      t += 4;
      x += 4;
   }
   for(size_t i = N % 4; i != 0; --i) {
      *out++ = word_madd3(*x++, b, *t++, &carry);
   }

   word c2 = 0;
   out[0] = word_add(t[0], carry, &c2);
   out[1] = word_add(t[1], c, &c2);
   return c2;
}

}  // namespace

void bigint_mulx_monty_mul(word z[], const word x[], const word y[], const word p[], size_t N, word p_dash, word ws[]) {
   // t[-1] receives the word shifted out by each reduction row
   word* t = ws + 1;
   clear_mem(ws, N + 3);

   for(size_t i = 0; i != N; ++i) {
      monty_row(t, t, x, N, y[i], 0);
      const word m = t[0] * p_dash;
      monty_row(t - 1, t, p, N, m, 0);
      t[N + 1] = 0;
   }

   // The result is below 2p, with t[N] holding its top bit
   bigint_monty_maybe_sub(N, z, t[N], t, p);
}

void bigint_mulx_monty_sqr(word z[], const word x[], const word p[], size_t N, word p_dash, word ws[]) {
   // Below this many words the rows of the triangular squaring are too short
   // to amortize their setup, and squaring via the fused multiplication wins
   constexpr size_t MulxMontySqrMinWords = 24;

   if(N < MulxMontySqrMinWords) {
      return bigint_mulx_monty_mul(z, x, x, p, N, p_dash, ws);
   } else {
      bigint_mulx_sqr(ws, x, N);
      return bigint_mulx_monty_redc(z, ws, p, N, p_dash);
   }
}

void bigint_mulx_sqr(word z[], const word x[], size_t N) {
   clear_mem(z, 2 * N + 1);

   // Each off-diagonal product x[i]*x[j] with j > i, once
   for(size_t i = 0; i + 1 < N; ++i) {
      monty_row(z + 2 * i + 1, z + 2 * i + 1, x + i + 1, N - i - 1, x[i], 0);
   }

   // Double them, then add the squares x[i]^2 along the diagonal
   bigint_shl1(z, 2 * N + 1, 2 * N, 1);

   word carry = 0;
   for(size_t i = 0; i != N; ++i) {
      word hi = 0;
      const word lo = word_madd2(x[i], x[i], &hi);
      z[2 * i] = word_add(z[2 * i], lo, &carry);
      z[2 * i + 1] = word_add(z[2 * i + 1], hi, &carry);
   }
}

void bigint_mulx_monty_redc(word r[], word z[], const word p[], size_t N, word p_dash) {
   z[2 * N] = 0;

   word c = 0;
   for(size_t i = 0; i != N; ++i) {
      const word m = z[i] * p_dash;
      c = monty_row(z + i, z + i, p, N, m, c);
   }

   // The sum is below 2p * B^N, so the final carry is zero and the top bit is z[2N]
   BOTAN_DEBUG_ASSERT(c == 0);
   bigint_monty_maybe_sub(N, r, z[2 * N], z + N, p);
}

}  // namespace Botan

#undef BOTAN_MULADD_STEP
#undef BOTAN_MULADD_ASM
#undef BOTAN_MULADD_STEPS4
#undef BOTAN_MULADD_STEPS8
