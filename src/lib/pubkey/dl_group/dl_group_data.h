/*
* Discrete Logarithm Group Data
* (C) 1999-2008,2015,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DL_GROUP_DATA_H_
#define BOTAN_DL_GROUP_DATA_H_

#include <botan/bigint.h>
#include <botan/dl_group.h>
#include <botan/internal/barrett.h>
#include <botan/internal/monty.h>
#include <memory>
#include <optional>
#include <string_view>

namespace Botan {

class Montgomery_Exponentiation_State;

class DL_Group_Data final {
   public:
      static std::shared_ptr<DL_Group_Data> create(const BigInt& p,
                                                   const BigInt& q,
                                                   const BigInt& g,
                                                   DL_Group_Source source);

      static std::shared_ptr<DL_Group_Data> create(const BigInt& p, const BigInt& g, DL_Group_Source source);

      // This constructor is public because C++ is terrible but all DL_Group_Data should
      // be created via DL_Group_Data::create
      DL_Group_Data(const BigInt& p, const BigInt& q, const BigInt& g, DL_Group_Source source);

      // This constructor is public because C++ is terrible but all DL_Group_Data should
      // be created via DL_Group_Data::create
      DL_Group_Data(const BigInt& p, const BigInt& g, DL_Group_Source source);

      ~DL_Group_Data() = default;

      DL_Group_Data(const DL_Group_Data& other) = delete;
      DL_Group_Data(DL_Group_Data&& other) = delete;
      DL_Group_Data& operator=(const DL_Group_Data& other) = delete;
      DL_Group_Data& operator=(DL_Group_Data&& other) = delete;

      const BigInt& p() const { return m_p; }

      const BigInt& q() const { return m_q; }

      const BigInt& g() const { return m_g; }

      const Barrett_Reduction& reducer_mod_p() const { return m_mod_p; }

      const Barrett_Reduction& reducer_mod_q() const {
         BOTAN_STATE_CHECK(m_mod_q);
         return *m_mod_q;
      }

      const Montgomery_Params& monty_params_p() const { return m_monty_params; }

      const Montgomery_Params& monty_params_q() const {
         BOTAN_STATE_CHECK(m_monty_q);
         return *m_monty_q;
      }

      size_t p_bits() const { return m_p_bits; }

      size_t q_bits() const { return m_q_bits; }

      size_t p_bytes() const { return (m_p_bits + 7) / 8; }

      size_t q_bytes() const { return (m_q_bits + 7) / 8; }

      size_t estimated_strength() const { return m_estimated_strength; }

      size_t exponent_bits() const { return m_exponent_bits; }

      Montgomery_Int monty_power_g_p(const BigInt& k, size_t max_k_bits) const;

      BigInt power_g_p(const BigInt& k, size_t max_k_bits) const;

      BigInt power_g_p_vartime(const BigInt& k) const;

      BigInt power_b_p(const BigInt& b, const BigInt& k, size_t max_k_bits) const;

      BigInt power_b_p_vartime(const BigInt& b, const BigInt& k) const;

      bool q_is_set() const { return m_q_bits > 0; }

      void assert_q_is_set(std::string_view function) const;

      DL_Group_Source source() const { return m_source; }

   private:
      BigInt m_p;
      BigInt m_q;  // zero if no q set
      BigInt m_g;
      Barrett_Reduction m_mod_p;
      std::optional<Barrett_Reduction> m_mod_q;
      Montgomery_Params m_monty_params;
      std::optional<Montgomery_Params> m_monty_q;
      std::shared_ptr<const Montgomery_Exponentiation_State> m_monty;
      size_t m_p_bits;
      size_t m_q_bits;
      size_t m_estimated_strength;
      size_t m_exponent_bits;
      DL_Group_Source m_source;
};

}  // namespace Botan

#endif
