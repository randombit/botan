/*
 * (C) Copyright Projet SECRET, INRIA, Rocquencourt
 * (C) Bhaskar Biswas and  Nicolas Sendrier
 *
 * (C) 2014 cryptosource GmbH
 * (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
 * (C) 2015 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 *
 */

#include <botan/internal/polyn_gf2m.h>

#include <botan/exceptn.h>
#include <botan/rng.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/code_based_util.h>
#include <botan/internal/loadstor.h>

namespace Botan {

namespace {

gf2m generate_gf2m_mask(gf2m a) {
   gf2m result = (a != 0);
   return ~(result - 1);
}

/**
* number of leading zeros
*/
unsigned nlz_16bit(uint16_t x) {
   unsigned n;
   if(x == 0) {
      return 16;
   }
   n = 0;
   if(x <= 0x00FF) {
      n = n + 8;
      x = x << 8;
   }
   if(x <= 0x0FFF) {
      n = n + 4;
      x = x << 4;
   }
   if(x <= 0x3FFF) {
      n = n + 2;
      x = x << 2;
   }
   if(x <= 0x7FFF) {
      n = n + 1;
   }
   return n;
}
}  // namespace

int polyn_gf2m::calc_degree_secure() const {
   int i = static_cast<int>(this->m_coeff.size()) - 1;
   int result = 0;
   uint32_t found_mask = 0;
   uint32_t tracker_mask = 0xffff;
   for(; i >= 0; i--) {
      found_mask = expand_mask_16bit(this->m_coeff[i]);
      result |= i & found_mask & tracker_mask;
      // tracker mask shall become zero once found mask is set
      // it shall remain zero from then on
      tracker_mask = tracker_mask & ~found_mask;
   }
   const_cast<polyn_gf2m*>(this)->m_deg = result;
   return result;
}

gf2m random_gf2m(RandomNumberGenerator& rng) {
   uint8_t b[2];
   rng.randomize(b, sizeof(b));
   return make_uint16(b[1], b[0]);
}

gf2m random_code_element(uint16_t code_length, RandomNumberGenerator& rng) {
   if(code_length == 0) {
      throw Invalid_Argument("random_code_element() was supplied a code length of zero");
   }
   const unsigned nlz = nlz_16bit(code_length - 1);
   const gf2m mask = (1 << (16 - nlz)) - 1;

   gf2m result;

   do {
      result = random_gf2m(rng);
      result &= mask;
   } while(result >= code_length);  // rejection sampling

   return result;
}

polyn_gf2m::polyn_gf2m(const polyn_gf2m& other) = default;

polyn_gf2m::polyn_gf2m(int d, const std::shared_ptr<GF2m_Field>& sp_field) :
      m_deg(-1), m_coeff(d + 1), m_sp_field(sp_field) {}

/**
* doesn't save coefficients:
*/
void polyn_gf2m::realloc(uint32_t new_size) {
   this->m_coeff = secure_vector<gf2m>(new_size);
}

polyn_gf2m::polyn_gf2m(const uint8_t* mem, uint32_t mem_len, const std::shared_ptr<GF2m_Field>& sp_field) :
      m_deg(-1), m_sp_field(sp_field) {
   if(mem_len % sizeof(gf2m)) {
      throw Decoding_Error("illegal length of memory to decode ");
   }

   uint32_t size = (mem_len / sizeof(this->m_coeff[0]));
   this->m_coeff = secure_vector<gf2m>(size);
   this->m_deg = -1;
   for(uint32_t i = 0; i < size; i++) {
      this->m_coeff[i] = decode_gf2m(mem);
      mem += sizeof(this->m_coeff[0]);
   }
   for(uint32_t i = 0; i < size; i++) {
      if(this->m_coeff[i] >= (1 << sp_field->get_extension_degree())) {
         throw Decoding_Error("error decoding polynomial");
      }
   }
   this->get_degree();
}

polyn_gf2m::polyn_gf2m(const std::shared_ptr<GF2m_Field>& sp_field) : m_deg(-1), m_coeff(1), m_sp_field(sp_field) {}

polyn_gf2m::polyn_gf2m(int degree,
                       const uint8_t* mem,
                       size_t mem_byte_len,
                       const std::shared_ptr<GF2m_Field>& sp_field) :
      m_sp_field(sp_field) {
   uint32_t j, k, l;
   gf2m a;
   uint32_t polyn_size;
   polyn_size = degree + 1;
   if(polyn_size * sp_field->get_extension_degree() > 8 * mem_byte_len) {
      throw Decoding_Error("memory vector for polynomial has wrong size");
   }
   this->m_coeff = secure_vector<gf2m>(degree + 1);
   gf2m ext_deg = static_cast<gf2m>(this->m_sp_field->get_extension_degree());
   for(l = 0; l < polyn_size; l++) {
      k = (l * ext_deg) / 8;

      j = (l * ext_deg) % 8;
      a = mem[k] >> j;
      if(j + ext_deg > 8) {
         a ^= mem[k + 1] << (8 - j);
      }
      if(j + ext_deg > 16) {
         a ^= mem[k + 2] << (16 - j);
      }
      a &= ((1 << ext_deg) - 1);
      (*this).set_coef(l, a);
   }

   this->get_degree();
}

void polyn_gf2m::set_to_zero() {
   clear_mem(&this->m_coeff[0], this->m_coeff.size());
   this->m_deg = -1;
}

int polyn_gf2m::get_degree() const {
   int d = static_cast<int>(this->m_coeff.size()) - 1;
   while((d >= 0) && (this->m_coeff[d] == 0)) {
      --d;
   }
   const_cast<polyn_gf2m*>(this)->m_deg = d;
   return d;
}

namespace {

gf2m eval_aux(const gf2m* /*restrict*/ coeff, gf2m a, int d, const std::shared_ptr<GF2m_Field>& sp_field) {
   gf2m b;
   b = coeff[d--];
   for(; d >= 0; --d) {
      if(b != 0) {
         b = sp_field->gf_mul(b, a) ^ coeff[d];
      } else {
         b = coeff[d];
      }
   }
   return b;
}

}  // namespace

gf2m polyn_gf2m::eval(gf2m a) {
   return eval_aux(&this->m_coeff[0], a, this->m_deg, this->m_sp_field);
}

// p will contain it's remainder modulo g
void polyn_gf2m::remainder(polyn_gf2m& p, const polyn_gf2m& g) {
   int i, j, d;
   std::shared_ptr<GF2m_Field> m_sp_field = g.m_sp_field;
   d = p.get_degree() - g.get_degree();
   if(d >= 0) {
      gf2m la = m_sp_field->gf_inv_rn(g.get_lead_coef());

      const int p_degree = p.get_degree();

      BOTAN_ASSERT(p_degree > 0, "Valid polynomial");

      for(i = p_degree; d >= 0; --i, --d) {
         if(p[i] != 0) {
            gf2m lb = m_sp_field->gf_mul_rrn(la, p[i]);
            for(j = 0; j < g.get_degree(); ++j) {
               p[j + d] ^= m_sp_field->gf_mul_zrz(lb, g[j]);
            }
            (*&p).set_coef(i, 0);
         }
      }
      p.set_degree(g.get_degree() - 1);
      while((p.get_degree() >= 0) && (p[p.get_degree()] == 0)) {
         p.set_degree(p.get_degree() - 1);
      }
   }
}

std::vector<polyn_gf2m> polyn_gf2m::sqmod_init(const polyn_gf2m& g) {
   std::vector<polyn_gf2m> sq;
   const int signed_deg = g.get_degree();
   if(signed_deg <= 0) {
      throw Invalid_Argument("cannot compute sqmod for such low degree");
   }

   const uint32_t d = static_cast<uint32_t>(signed_deg);
   uint32_t t = g.m_deg;
   // create t zero polynomials
   uint32_t i;
   for(i = 0; i < t; ++i) {
      sq.push_back(polyn_gf2m(t + 1, g.get_sp_field()));
   }
   for(i = 0; i < d / 2; ++i) {
      sq[i].set_degree(2 * i);
      (*&sq[i]).set_coef(2 * i, 1);
   }

   for(; i < d; ++i) {
      clear_mem(&sq[i].m_coeff[0], 2);
      copy_mem(&sq[i].m_coeff[0] + 2, &sq[i - 1].m_coeff[0], d);
      sq[i].set_degree(sq[i - 1].get_degree() + 2);
      polyn_gf2m::remainder(sq[i], g);
   }
   return sq;
}

/*Modulo p square of a certain polynomial g, sq[] contains the square
Modulo g of the base canonical polynomials of degree < d, where d is
the degree of G. The table sq[] will be calculated by polyn_gf2m_sqmod_init*/
polyn_gf2m polyn_gf2m::sqmod(const std::vector<polyn_gf2m>& sq, int d) {
   int i, j;
   gf2m la;
   std::shared_ptr<GF2m_Field> sp_field = this->m_sp_field;

   polyn_gf2m result(d - 1, sp_field);
   // terms of low degree
   for(i = 0; i < d / 2; ++i) {
      (*&result).set_coef(i * 2, sp_field->gf_square((*this)[i]));
   }

   // terms of high degree
   for(; i < d; ++i) {
      gf2m lpi = (*this)[i];
      if(lpi != 0) {
         lpi = sp_field->gf_log(lpi);
         la = sp_field->gf_mul_rrr(lpi, lpi);
         for(j = 0; j < d; ++j) {
            result[j] ^= sp_field->gf_mul_zrz(la, sq[i][j]);
         }
      }
   }

   // Update degre
   result.set_degree(d - 1);
   while((result.get_degree() >= 0) && (result[result.get_degree()] == 0)) {
      result.set_degree(result.get_degree() - 1);
   }
   return result;
}

// destructive
polyn_gf2m polyn_gf2m::gcd_aux(polyn_gf2m& p1, polyn_gf2m& p2) {
   if(p2.get_degree() == -1) {
      return p1;
   } else {
      polyn_gf2m::remainder(p1, p2);
      return polyn_gf2m::gcd_aux(p2, p1);
   }
}

polyn_gf2m polyn_gf2m::gcd(const polyn_gf2m& p1, const polyn_gf2m& p2) {
   polyn_gf2m a(p1);
   polyn_gf2m b(p2);
   if(a.get_degree() < b.get_degree()) {
      return polyn_gf2m(polyn_gf2m::gcd_aux(b, a));
   } else {
      return polyn_gf2m(polyn_gf2m::gcd_aux(a, b));
   }
}

// Returns the degree of the smallest factor
size_t polyn_gf2m::degppf(const polyn_gf2m& g) {
   polyn_gf2m s(g.get_sp_field());

   const size_t ext_deg = g.m_sp_field->get_extension_degree();
   const int d = g.get_degree();
   std::vector<polyn_gf2m> u = polyn_gf2m::sqmod_init(g);

   polyn_gf2m p(d - 1, g.m_sp_field);

   p.set_degree(1);
   (*&p).set_coef(1, 1);
   size_t result = static_cast<size_t>(d);
   for(size_t i = 1; i <= (d / 2) * ext_deg; ++i) {
      polyn_gf2m r = p.sqmod(u, d);
      if((i % ext_deg) == 0) {
         r[1] ^= 1;
         r.get_degree();  // The degree may change
         s = polyn_gf2m::gcd(g, r);

         if(s.get_degree() > 0) {
            result = i / ext_deg;
            break;
         }
         r[1] ^= 1;
         r.get_degree();  // The degree may change
      }
      // No need for the exchange s
      s = p;
      p = r;
      r = s;
   }

   return result;
}

void polyn_gf2m::patchup_deg_secure(uint32_t trgt_deg, gf2m patch_elem) {
   uint32_t i;
   if(this->m_coeff.size() < trgt_deg) {
      return;
   }
   for(i = 0; i < this->m_coeff.size(); i++) {
      uint32_t equal, equal_mask;
      this->m_coeff[i] |= patch_elem;
      equal = (i == trgt_deg);
      equal_mask = expand_mask_16bit(equal);
      patch_elem &= ~equal_mask;
   }
   this->calc_degree_secure();
}

// We suppose m_deg(g) >= m_deg(p)
// v is the problem
std::pair<polyn_gf2m, polyn_gf2m> polyn_gf2m::eea_with_coefficients(const polyn_gf2m& p,
                                                                    const polyn_gf2m& g,
                                                                    int break_deg) {
   std::shared_ptr<GF2m_Field> m_sp_field = g.m_sp_field;
   int i, j, dr, du, delta;
   gf2m a;
   polyn_gf2m aux;

   // initialisation of the local variables
   // r0 <- g, r1 <- p, u0 <- 0, u1 <- 1
   dr = g.get_degree();

   BOTAN_ASSERT(dr > 3, "Valid polynomial");

   polyn_gf2m r0(dr, g.m_sp_field);
   polyn_gf2m r1(dr - 1, g.m_sp_field);
   polyn_gf2m u0(dr - 1, g.m_sp_field);
   polyn_gf2m u1(dr - 1, g.m_sp_field);

   r0 = g;
   r1 = p;
   u0.set_to_zero();
   u1.set_to_zero();
   (*&u1).set_coef(0, 1);
   u1.set_degree(0);

   // invariants:
   // r1 = u1 * p + v1 * g
   // r0 = u0 * p + v0 * g
   // and m_deg(u1) = m_deg(g) - m_deg(r0)
   // It stops when m_deg (r1) <t (m_deg (r0)> = t)
   // And therefore m_deg (u1) = m_deg (g) - m_deg (r0) <m_deg (g) - break_deg
   du = 0;
   dr = r1.get_degree();
   delta = r0.get_degree() - dr;

   while(dr >= break_deg) {
      for(j = delta; j >= 0; --j) {
         a = m_sp_field->gf_div(r0[dr + j], r1[dr]);
         if(a != 0) {
            gf2m la = m_sp_field->gf_log(a);
            // u0(z) <- u0(z) + a * u1(z) * z^j
            for(i = 0; i <= du; ++i) {
               u0[i + j] ^= m_sp_field->gf_mul_zrz(la, u1[i]);
            }
            // r0(z) <- r0(z) + a * r1(z) * z^j
            for(i = 0; i <= dr; ++i) {
               r0[i + j] ^= m_sp_field->gf_mul_zrz(la, r1[i]);
            }
         }
      }  // end loop over j

      if(break_deg != 1) /* key eq. solving */
      {
         /* [ssms_icisc09] Countermeasure
         * d_break from paper equals break_deg - 1
         * */

         volatile gf2m fake_elem = 0x01;
         volatile gf2m cond1, cond2;
         int trgt_deg = r1.get_degree() - 1;
         r0.calc_degree_secure();
         u0.calc_degree_secure();
         if(!(g.get_degree() % 2)) {
            /* t even */
            cond1 = r0.get_degree() < break_deg - 1;
         } else {
            /* t odd */
            cond1 = r0.get_degree() < break_deg;
            cond2 = u0.get_degree() < break_deg - 1;
            cond1 = cond1 & cond2;
         }
         /* expand cond1 to a full mask */
         gf2m mask = generate_gf2m_mask(cond1);
         fake_elem = fake_elem & mask;
         r0.patchup_deg_secure(trgt_deg, fake_elem);
      }
      if(break_deg == 1) /* syndrome inversion */
      {
         volatile gf2m fake_elem = 0x00;
         volatile uint32_t trgt_deg = 0;
         r0.calc_degree_secure();
         u0.calc_degree_secure();
         /**
         * countermeasure against the low weight attacks for w=4, w=6 and w=8.
         * Higher values are not covered since for w=8 we already have a
         * probability for a positive of 1/n^3 from random ciphertexts with the
         * given weight. For w = 10 it would be 1/n^4 and so on. Thus attacks
         * based on such high values of w are considered impractical.
         *
         * The outer test for the degree of u ( Omega in the paper ) needs not to
         * be disguised. Each of the three is performed at most once per EEA
         * (syndrome inversion) execution, the attacker knows this already when
         * preparing the ciphertext with the given weight. Inside these three
         * cases however, we must use timing neutral (branch free) operations to
         * implement the condition detection and the counteractions.
         *
         */
         if(u0.get_degree() == 4) {
            uint32_t mask = 0;
            /**
            * Condition that the EEA would break now
            */
            int cond_r = r0.get_degree() == 0;
            /**
            * Now come the conditions for all odd coefficients of this sigma
            * candiate. If they are all fulfilled, then we know that we have a low
            * weight error vector, since the key-equation solving EEA is skipped if
            * the degree of tau^2 is low (=m_deg(u0)) and all its odd cofficients are
            * zero (they would cause "full-length" contributions from the square
            * root computation).
            */
            // Condition for the coefficient to Y to be cancelled out by the
            // addition of Y before the square root computation:
            int cond_u1 = m_sp_field->gf_mul(u0.m_coeff[1], m_sp_field->gf_inv(r0.m_coeff[0])) == 1;

            // Condition sigma_3 = 0:
            int cond_u3 = u0.m_coeff[3] == 0;
            // combine the conditions:
            cond_r &= (cond_u1 & cond_u3);
            // mask generation:
            mask = expand_mask_16bit(cond_r);
            trgt_deg = 2 & mask;
            fake_elem = 1 & mask;
         } else if(u0.get_degree() == 6) {
            uint32_t mask = 0;
            int cond_r = r0.get_degree() == 0;
            int cond_u1 = m_sp_field->gf_mul(u0.m_coeff[1], m_sp_field->gf_inv(r0.m_coeff[0])) == 1;
            int cond_u3 = u0.m_coeff[3] == 0;

            int cond_u5 = u0.m_coeff[5] == 0;

            cond_r &= (cond_u1 & cond_u3 & cond_u5);
            mask = expand_mask_16bit(cond_r);
            trgt_deg = 4 & mask;
            fake_elem = 1 & mask;
         } else if(u0.get_degree() == 8) {
            uint32_t mask = 0;
            int cond_r = r0.get_degree() == 0;
            int cond_u1 = m_sp_field->gf_mul(u0[1], m_sp_field->gf_inv(r0[0])) == 1;
            int cond_u3 = u0.m_coeff[3] == 0;

            int cond_u5 = u0.m_coeff[5] == 0;

            int cond_u7 = u0.m_coeff[7] == 0;

            cond_r &= (cond_u1 & cond_u3 & cond_u5 & cond_u7);
            mask = expand_mask_16bit(cond_r);
            trgt_deg = 6 & mask;
            fake_elem = 1 & mask;
         }
         r0.patchup_deg_secure(trgt_deg, fake_elem);
      }
      // exchange
      aux = r0;
      r0 = r1;
      r1 = aux;
      aux = u0;
      u0 = u1;
      u1 = aux;

      du = du + delta;
      delta = 1;
      while(r1[dr - delta] == 0) {
         delta++;
      }

      dr -= delta;
   } /* end  while loop (dr >= break_deg) */

   u1.set_degree(du);
   r1.set_degree(dr);
   //return u1 and r1;
   return std::make_pair(u1, r1);  // coefficients u,v
}

polyn_gf2m::polyn_gf2m(size_t t, RandomNumberGenerator& rng, const std::shared_ptr<GF2m_Field>& sp_field) :
      m_deg(static_cast<int>(t)), m_coeff(t + 1), m_sp_field(sp_field) {
   this->set_coef(t, 1);
   for(;;) {
      for(size_t i = 0; i < t; ++i) {
         this->set_coef(i, random_code_element(sp_field->get_cardinality(), rng));
      }

      const size_t degree = polyn_gf2m::degppf(*this);

      if(degree >= t) {
         break;
      }
   }
}

void polyn_gf2m::poly_shiftmod(const polyn_gf2m& g) {
   if(g.get_degree() <= 1) {
      throw Invalid_Argument("shiftmod cannot be called on polynomials of degree 1 or less");
   }
   std::shared_ptr<GF2m_Field> field = g.m_sp_field;

   int t = g.get_degree();
   gf2m a = field->gf_div(this->m_coeff[t - 1], g.m_coeff[t]);
   for(int i = t - 1; i > 0; --i) {
      this->m_coeff[i] = this->m_coeff[i - 1] ^ this->m_sp_field->gf_mul(a, g.m_coeff[i]);
   }
   this->m_coeff[0] = field->gf_mul(a, g.m_coeff[0]);
}

std::vector<polyn_gf2m> polyn_gf2m::sqrt_mod_init(const polyn_gf2m& g) {
   uint32_t i, t;
   uint32_t nb_polyn_sqrt_mat;
   std::shared_ptr<GF2m_Field> m_sp_field = g.m_sp_field;
   std::vector<polyn_gf2m> result;
   t = g.get_degree();
   nb_polyn_sqrt_mat = t / 2;

   std::vector<polyn_gf2m> sq_aux = polyn_gf2m::sqmod_init(g);

   polyn_gf2m p(t - 1, g.get_sp_field());
   p.set_degree(1);

   (*&p).set_coef(1, 1);
   // q(z) = 0, p(z) = z
   for(i = 0; i < t * m_sp_field->get_extension_degree() - 1; ++i) {
      // q(z) <- p(z)^2 mod g(z)
      polyn_gf2m q = p.sqmod(sq_aux, t);
      // q(z) <-> p(z)
      polyn_gf2m aux = q;
      q = p;
      p = aux;
   }
   // p(z) = z^(2^(tm-1)) mod g(z) = sqrt(z) mod g(z)

   for(i = 0; i < nb_polyn_sqrt_mat; ++i) {
      result.push_back(polyn_gf2m(t - 1, g.get_sp_field()));
   }

   result[0] = p;
   result[0].get_degree();
   for(i = 1; i < nb_polyn_sqrt_mat; i++) {
      result[i] = result[i - 1];
      result[i].poly_shiftmod(g);
      result[i].get_degree();
   }

   return result;
}

std::vector<polyn_gf2m> syndrome_init(const polyn_gf2m& generator, const std::vector<gf2m>& support, int n) {
   int i, j, t;
   gf2m a;

   std::shared_ptr<GF2m_Field> m_sp_field = generator.get_sp_field();

   std::vector<polyn_gf2m> result;
   t = generator.get_degree();

   //g(z)=g_t+g_(t-1).z^(t-1)+......+g_1.z+g_0
   //f(z)=f_(t-1).z^(t-1)+......+f_1.z+f_0

   for(j = 0; j < n; j++) {
      result.push_back(polyn_gf2m(t - 1, m_sp_field));

      (*&result[j]).set_coef(t - 1, 1);
      for(i = t - 2; i >= 0; i--) {
         (*&result[j]).set_coef(i, (generator)[i + 1] ^ m_sp_field->gf_mul(lex_to_gray(support[j]), result[j][i + 1]));
      }
      a = ((generator)[0] ^ m_sp_field->gf_mul(lex_to_gray(support[j]), result[j][0]));
      for(i = 0; i < t; i++) {
         (*&result[j]).set_coef(i, m_sp_field->gf_div(result[j][i], a));
      }
   }
   return result;
}

polyn_gf2m::polyn_gf2m(const secure_vector<uint8_t>& encoded, const std::shared_ptr<GF2m_Field>& sp_field) :
      m_sp_field(sp_field) {
   if(encoded.size() % 2) {
      throw Decoding_Error("encoded polynomial has odd length");
   }
   for(uint32_t i = 0; i < encoded.size(); i += 2) {
      gf2m el = (encoded[i] << 8) | encoded[i + 1];
      m_coeff.push_back(el);
   }
   get_degree();
}

secure_vector<uint8_t> polyn_gf2m::encode() const {
   secure_vector<uint8_t> result;

   if(m_deg < 1) {
      result.push_back(0);
      result.push_back(0);
      return result;
   }

   uint32_t len = m_deg + 1;
   for(unsigned i = 0; i < len; i++) {
      // "big endian" encoding of the GF(2^m) elements
      result.push_back(get_byte<0>(m_coeff[i]));
      result.push_back(get_byte<1>(m_coeff[i]));
   }
   return result;
}

void polyn_gf2m::swap(polyn_gf2m& other) noexcept {
   std::swap(this->m_deg, other.m_deg);
   std::swap(this->m_sp_field, other.m_sp_field);
   std::swap(this->m_coeff, other.m_coeff);
}

bool polyn_gf2m::operator==(const polyn_gf2m& other) const {
   if(m_deg != other.m_deg || m_coeff != other.m_coeff) {
      return false;
   }
   return true;
}

}  // namespace Botan
