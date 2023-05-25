/*
 * (C) 2014 cryptosource GmbH
 * (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 *
 */

#include <botan/internal/polyn_gf2m.h>

#include <botan/exceptn.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/code_based_util.h>

namespace Botan {

namespace {

void patch_root_array(gf2m res_root_arr[], size_t res_root_arr_len, size_t root_pos) {
   volatile gf2m patch_elem = 0x01;
   volatile gf2m cond_mask = (root_pos == res_root_arr_len);
   cond_mask = expand_mask_16bit(cond_mask);
   cond_mask = ~cond_mask; /* now cond = 1 if not enough roots */
   patch_elem = patch_elem & cond_mask;
   for(size_t i = 0; i < res_root_arr_len; i++) {
      patch_elem = patch_elem + 1;
      gf2m masked_patch_elem = patch_elem & cond_mask;
      res_root_arr[i] ^= masked_patch_elem++;
   }
}

class gf2m_decomp_rootfind_state {
   public:
      gf2m_decomp_rootfind_state(const polyn_gf2m& p_polyn, size_t code_length);

      void calc_LiK(const polyn_gf2m& sigma);
      gf2m calc_Fxj_j_neq_0(const polyn_gf2m& sigma, gf2m j_gray);
      void calc_next_Aij();
      void calc_Ai_zero(const polyn_gf2m& sigma);
      secure_vector<gf2m> find_roots(const polyn_gf2m& sigma);

   private:
      size_t m_code_length;
      secure_vector<gf2m> m_Lik;  // size is outer_summands * m
      secure_vector<gf2m> m_Aij;  // ...
      uint32_t m_outer_summands;
      gf2m m_j;
      gf2m m_j_gray;
      gf2m m_sigma_3_l;
      gf2m m_sigma_3_neq_0_mask;
};

/**
* calculates ceil((t-4)/5) = outer_summands - 1
*/
uint32_t brootf_decomp_calc_sum_limit(uint32_t t) {
   uint32_t result;
   if(t < 4) {
      return 0;
   }
   result = t - 4;
   result += 4;
   result /= 5;
   return result;
}

gf2m_decomp_rootfind_state::gf2m_decomp_rootfind_state(const polyn_gf2m& polyn, size_t code_length) :
      m_code_length(code_length), m_j(0), m_j_gray(0) {
   gf2m coeff_3;
   gf2m coeff_head;
   std::shared_ptr<GF2m_Field> sp_field = polyn.get_sp_field();
   int deg_sigma = polyn.get_degree();
   if(deg_sigma <= 3) {
      throw Internal_Error("Unexpected degree in gf2m_decomp_rootfind_state");
   }

   coeff_3 = polyn.get_coef(3);
   coeff_head = polyn.get_coef(deg_sigma); /* dummy value for SCA CM */
   if(coeff_3 != 0) {
      this->m_sigma_3_l = sp_field->gf_l_from_n(coeff_3);
      this->m_sigma_3_neq_0_mask = 0xFFFF;
   } else {
      // dummy value needed for timing countermeasure
      this->m_sigma_3_l = sp_field->gf_l_from_n(coeff_head);
      this->m_sigma_3_neq_0_mask = 0;
   }

   this->m_outer_summands = 1 + brootf_decomp_calc_sum_limit(deg_sigma);
   this->m_Lik.resize(this->m_outer_summands * sp_field->get_extension_degree());
   this->m_Aij.resize(this->m_outer_summands);
}

void gf2m_decomp_rootfind_state::calc_Ai_zero(const polyn_gf2m& sigma) {
   uint32_t i;
   /*
   * this function assumes this the first gray code element is zero
   */
   for(i = 0; i < this->m_outer_summands; i++) {
      this->m_Aij[i] = sigma.get_coef(5 * i);
   }
   this->m_j = 0;
   this->m_j_gray = 0;
}

void gf2m_decomp_rootfind_state::calc_next_Aij() {
   /*
   * upon function entry, we have in the state j, Aij.
   * first thing, we declare Aij Aij_minusone and increase j.
   * Case j=0 upon function entry also included, then Aij contains A_{i,j=0}.
   */
   uint32_t i;
   gf2m diff, new_j_gray;
   uint32_t Lik_pos_base;

   this->m_j++;

   new_j_gray = lex_to_gray(this->m_j);

   if(this->m_j & 1) /* half of the times */
   {
      Lik_pos_base = 0;
   } else if(this->m_j & 2) /* one quarter of the times */
   {
      Lik_pos_base = this->m_outer_summands;
   } else if(this->m_j & 4) /* one eighth of the times */
   {
      Lik_pos_base = this->m_outer_summands * 2;
   } else if(this->m_j & 8) /* one sixteenth of the times */
   {
      Lik_pos_base = this->m_outer_summands * 3;
   } else if(this->m_j & 16) /* ... */
   {
      Lik_pos_base = this->m_outer_summands * 4;
   } else {
      gf2m delta_offs = 5;
      diff = this->m_j_gray ^ new_j_gray;
      while(((static_cast<gf2m>(1) << delta_offs) & diff) == 0) {
         delta_offs++;
      }
      Lik_pos_base = delta_offs * this->m_outer_summands;
   }
   this->m_j_gray = new_j_gray;

   i = 0;
   for(; i < this->m_outer_summands; i++) {
      this->m_Aij[i] ^= this->m_Lik[Lik_pos_base + i];
   }
}

void gf2m_decomp_rootfind_state::calc_LiK(const polyn_gf2m& sigma) {
   std::shared_ptr<GF2m_Field> sp_field = sigma.get_sp_field();
   uint32_t i, k, d;
   d = sigma.get_degree();
   for(k = 0; k < sp_field->get_extension_degree(); k++) {
      uint32_t Lik_pos_base = k * this->m_outer_summands;
      gf2m alpha_l_k_tt2_ttj[4];
      alpha_l_k_tt2_ttj[0] = sp_field->gf_l_from_n(static_cast<gf2m>(1) << k);
      alpha_l_k_tt2_ttj[1] = sp_field->gf_mul_rrr(alpha_l_k_tt2_ttj[0], alpha_l_k_tt2_ttj[0]);
      alpha_l_k_tt2_ttj[2] = sp_field->gf_mul_rrr(alpha_l_k_tt2_ttj[1], alpha_l_k_tt2_ttj[1]);

      alpha_l_k_tt2_ttj[3] = sp_field->gf_mul_rrr(alpha_l_k_tt2_ttj[2], alpha_l_k_tt2_ttj[2]);
      for(i = 0; i < this->m_outer_summands; i++) {
         uint32_t j;
         uint32_t five_i = 5 * i;
         uint32_t Lik_pos = Lik_pos_base + i;
         this->m_Lik[Lik_pos] = 0;
         for(j = 0; j <= 3; j++) {
            gf2m f, x;
            uint32_t f_ind = five_i + (static_cast<uint32_t>(1) << j);
            if(f_ind > d) {
               break;
            }
            f = sigma.get_coef(f_ind);

            x = sp_field->gf_mul_zrz(alpha_l_k_tt2_ttj[j], f);
            this->m_Lik[Lik_pos] ^= x;
         }
      }
   }
}

gf2m gf2m_decomp_rootfind_state::calc_Fxj_j_neq_0(const polyn_gf2m& sigma, gf2m j_gray) {
   //needs the A_{ij} to compute F(x)_j
   gf2m sum = 0;
   uint32_t i;
   std::shared_ptr<GF2m_Field> sp_field = sigma.get_sp_field();
   const gf2m jl_gray = sp_field->gf_l_from_n(j_gray);
   gf2m xl_j_tt_5 = sp_field->gf_square_rr(jl_gray);
   gf2m xl_gray_tt_3 = sp_field->gf_mul_rrr(xl_j_tt_5, jl_gray);
   xl_j_tt_5 = sp_field->gf_mul_rrr(xl_j_tt_5, xl_gray_tt_3);

   sum = sp_field->gf_mul_nrr(xl_gray_tt_3, this->m_sigma_3_l);
   sum &= this->m_sigma_3_neq_0_mask;
   /* here, we rely on compiler to be unable to optimize
   * for the state->sigma_3_neq_0_mask value
   */
   /* treat i = 0 special: */
   sum ^= this->m_Aij[0];
   /* treat i = 1 special also */

   if(this->m_outer_summands > 1) {
      gf2m x;
      x = sp_field->gf_mul_zrz(xl_j_tt_5, this->m_Aij[1]); /* x_j^{5i} A_i^j */
      sum ^= x;
   }

   gf2m xl_j_tt_5i = xl_j_tt_5;

   for(i = 2; i < this->m_outer_summands; i++) {
      gf2m x;
      xl_j_tt_5i = sp_field->gf_mul_rrr(xl_j_tt_5i, xl_j_tt_5);
      // now x_j_tt_5i lives up to its name
      x = sp_field->gf_mul_zrz(xl_j_tt_5i, this->m_Aij[i]); /* x_j^{5i} A_i^(j) */
      sum ^= x;
   }
   return sum;
}

secure_vector<gf2m> gf2m_decomp_rootfind_state::find_roots(const polyn_gf2m& sigma) {
   const int sigma_degree = sigma.get_degree();
   BOTAN_ASSERT(sigma_degree > 0, "Valid sigma");
   secure_vector<gf2m> result(sigma_degree);
   uint32_t root_pos = 0;

   this->calc_Ai_zero(sigma);
   this->calc_LiK(sigma);
   for(;;) {
      gf2m eval_result;

      if(this->m_j_gray == 0) {
         eval_result = sigma.get_coef(0);
      } else {
         eval_result = this->calc_Fxj_j_neq_0(sigma, this->m_j_gray);
      }

      if(eval_result == 0) {
         result[root_pos] = this->m_j_gray;
         root_pos++;
      }

      if(this->m_j + static_cast<uint32_t>(1) == m_code_length) {
         break;
      }
      this->calc_next_Aij();
   }

   // side channel / fault attack countermeasure:
   patch_root_array(result.data(), result.size(), root_pos);
   return result;
}

}  // end anonymous namespace

secure_vector<gf2m> find_roots_gf2m_decomp(const polyn_gf2m& polyn, size_t code_length) {
   gf2m_decomp_rootfind_state state(polyn, code_length);
   return state.find_roots(polyn);
}

}  // end namespace Botan
