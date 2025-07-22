/*
* (C) 2018,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MONTY_INT_H_
#define BOTAN_MONTY_INT_H_

#include <botan/bigint.h>

#include <botan/internal/ct_utils.h>
#include <memory>
#include <span>

namespace Botan {

class Barrett_Reduction;

/**
* Parameters for Montgomery Reduction
*/
class BOTAN_TEST_API Montgomery_Params final {
   public:
      /**
      * Initialize a set of Montgomery reduction parameters. These values
      * can be shared by all values in a specific Montgomery domain.
      */
      Montgomery_Params(const BigInt& p, const Barrett_Reduction& mod_p);

      /**
      * Initialize a set of Montgomery reduction parameters. These values
      * can be shared by all values in a specific Montgomery domain.
      */
      explicit Montgomery_Params(const BigInt& p);

      bool operator==(const Montgomery_Params& other) const;

      bool operator!=(const Montgomery_Params& other) const { return !((*this) == other); }

      const BigInt& p() const { return m_data->p(); }

      const BigInt& R1() const { return m_data->r1(); }

      const BigInt& R2() const { return m_data->r2(); }

      const BigInt& R3() const { return m_data->r3(); }

      word p_dash() const { return m_data->p_dash(); }

      size_t p_words() const { return m_data->p_size(); }

      BigInt redc(const BigInt& x, secure_vector<word>& ws) const;

      void mul(BigInt& z, const BigInt& x, const BigInt& y, secure_vector<word>& ws) const;

      void mul(BigInt& z, const BigInt& x, std::span<const word> y, secure_vector<word>& ws) const;

      BigInt mul(const BigInt& x, const BigInt& y, secure_vector<word>& ws) const;

      void mul_by(BigInt& x, const BigInt& y, secure_vector<word>& ws) const;

      BigInt sqr(const BigInt& x, secure_vector<word>& ws) const;

      void sqr(BigInt& z, const BigInt& x, secure_vector<word>& ws) const;

      void sqr(BigInt& z, std::span<const word> x, secure_vector<word>& ws) const;

   private:
      BigInt sqr(std::span<const word> x, secure_vector<word>& ws) const;

      class Data final {
         public:
            Data(const BigInt& p, const Barrett_Reduction& mod_p);

            const BigInt& p() const { return m_p; }

            const BigInt& r1() const { return m_r1; }

            const BigInt& r2() const { return m_r2; }

            const BigInt& r3() const { return m_r3; }

            word p_dash() const { return m_p_dash; }

            size_t p_size() const { return m_p_words; }

         private:
            BigInt m_p;
            BigInt m_r1;
            BigInt m_r2;
            BigInt m_r3;
            word m_p_dash;
            size_t m_p_words;
      };

      std::shared_ptr<const Data> m_data;
};

/**
* The Montgomery representation of an integer
*/
class BOTAN_TEST_API Montgomery_Int final {
   public:
      /**
      * Create a zero-initialized Montgomery_Int
      */
      explicit Montgomery_Int(const Montgomery_Params& params) : m_params(params) {}

      /**
      * Create a Montgomery_Int from a BigInt
      */
      Montgomery_Int(const Montgomery_Params& params, const BigInt& v, bool redc_needed = true);

      /**
      * Create a Montgomery_Int
      *
      * The span must be exactly p_words long and encoding a value less than p already
      * in Montgomery form
      */
      Montgomery_Int(const Montgomery_Params& params, std::span<const word> words);

      /**
      * Return the value 1 in Montgomery form
      */
      static Montgomery_Int one(const Montgomery_Params& params);

      /**
      * Wide reduction - input can be at most 2*bytes long
      */
      static Montgomery_Int from_wide_int(const Montgomery_Params& params, const BigInt& x);

      std::vector<uint8_t> serialize() const;

      /**
      * Return the value to normal mod-p space
      */
      BigInt value() const;

      /**
      * Return the Montgomery representation
      */
      const secure_vector<word>& repr() const { return m_v; }

      Montgomery_Int operator+(const Montgomery_Int& other) const;

      Montgomery_Int operator-(const Montgomery_Int& other) const;

      Montgomery_Int mul(const Montgomery_Int& other, secure_vector<word>& ws) const;

      Montgomery_Int& mul_by(const Montgomery_Int& other, secure_vector<word>& ws);

      Montgomery_Int& mul_by(std::span<const word> other, secure_vector<word>& ws);

      Montgomery_Int square(secure_vector<word>& ws) const;

      Montgomery_Int& square_this_n_times(secure_vector<word>& ws, size_t n);

      void _const_time_poison() const { CT::poison(m_v); }

      void _const_time_unpoison() const { CT::unpoison(m_v); }

      const Montgomery_Params& _params() const { return m_params; }

   private:
      Montgomery_Int(const Montgomery_Params& params, secure_vector<word> words);

      Montgomery_Params m_params;
      secure_vector<word> m_v;
};

}  // namespace Botan

#endif
