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

namespace Botan {

class Modular_Reducer;

class Montgomery_Params;

/**
* The Montgomery representation of an integer
*/
class BOTAN_TEST_API Montgomery_Int final {
   public:
      /**
      * Create a zero-initialized Montgomery_Int
      */
      Montgomery_Int(std::shared_ptr<const Montgomery_Params> params) : m_params(std::move(params)) {}

      /**
      * Create a Montgomery_Int
      */
      Montgomery_Int(const std::shared_ptr<const Montgomery_Params>& params, const BigInt& v, bool redc_needed = true);

      /**
      * Create a Montgomery_Int
      */
      Montgomery_Int(const std::shared_ptr<const Montgomery_Params>& params,
                     const uint8_t bits[],
                     size_t len,
                     bool redc_needed = true);

      /**
      * Create a Montgomery_Int
      */
      Montgomery_Int(std::shared_ptr<const Montgomery_Params> params,
                     const word words[],
                     size_t len,
                     bool redc_needed = true);

      static Montgomery_Int one(const std::shared_ptr<const Montgomery_Params>& params);

      /**
      * Wide reduction - input can be at most 2*bytes long
      */
      static Montgomery_Int from_wide_int(const std::shared_ptr<const Montgomery_Params>& params, const BigInt& x);

      bool operator==(const Montgomery_Int& other) const;

      bool operator!=(const Montgomery_Int& other) const { return (m_v != other.m_v); }

      std::vector<uint8_t> serialize() const;

      size_t size() const;
      bool is_one() const;
      bool is_zero() const;

      void fix_size();

      /**
      * Return the value to normal mod-p space
      */
      BigInt value() const;

      /**
      * Return the Montgomery representation
      */
      const BigInt& repr() const { return m_v; }

      Montgomery_Int operator+(const Montgomery_Int& other) const;

      Montgomery_Int operator-(const Montgomery_Int& other) const;

      Montgomery_Int& operator+=(const Montgomery_Int& other);

      Montgomery_Int& operator-=(const Montgomery_Int& other);

      Montgomery_Int operator*(const Montgomery_Int& other) const;

      Montgomery_Int& operator*=(const Montgomery_Int& other);

      Montgomery_Int& operator*=(const secure_vector<word>& other);

      Montgomery_Int& add(const Montgomery_Int& other, secure_vector<word>& ws);

      Montgomery_Int& sub(const Montgomery_Int& other, secure_vector<word>& ws);

      Montgomery_Int mul(const Montgomery_Int& other, secure_vector<word>& ws) const;

      Montgomery_Int& mul_by(const Montgomery_Int& other, secure_vector<word>& ws);

      Montgomery_Int& mul_by(const secure_vector<word>& other, secure_vector<word>& ws);

      Montgomery_Int square(secure_vector<word>& ws) const;

      Montgomery_Int cube(secure_vector<word>& ws) const;

      Montgomery_Int& square_this(secure_vector<word>& ws);

      Montgomery_Int& square_this_n_times(secure_vector<word>& ws, size_t n);

      Montgomery_Int additive_inverse() const;

      Montgomery_Int& mul_by_2(secure_vector<word>& ws);

      Montgomery_Int& mul_by_3(secure_vector<word>& ws);

      Montgomery_Int& mul_by_4(secure_vector<word>& ws);

      Montgomery_Int& mul_by_8(secure_vector<word>& ws);

      void _const_time_poison() const { CT::poison(m_v); }

      void _const_time_unpoison() const { CT::unpoison(m_v); }

      const std::shared_ptr<const Montgomery_Params>& _params() const { return m_params; }

   private:
      std::shared_ptr<const Montgomery_Params> m_params;
      BigInt m_v;
};

/**
* Parameters for Montgomery Reduction
*/
class BOTAN_TEST_API Montgomery_Params final {
   public:
      /**
      * Initialize a set of Montgomery reduction parameters. These values
      * can be shared by all values in a specific Montgomery domain.
      */
      Montgomery_Params(const BigInt& p, const Modular_Reducer& mod_p);

      /**
      * Initialize a set of Montgomery reduction parameters. These values
      * can be shared by all values in a specific Montgomery domain.
      */
      Montgomery_Params(const BigInt& p);

      const BigInt& p() const { return m_p; }

      const BigInt& R1() const { return m_r1; }

      const BigInt& R2() const { return m_r2; }

      const BigInt& R3() const { return m_r3; }

      word p_dash() const { return m_p_dash; }

      size_t p_words() const { return m_p_words; }

      BigInt redc(const BigInt& x, secure_vector<word>& ws) const;

      void redc_in_place(BigInt& x, secure_vector<word>& ws) const;

      void mul(BigInt& z, const BigInt& x, const BigInt& y, secure_vector<word>& ws) const;

      void mul(BigInt& z, const BigInt& x, std::span<const word> y, secure_vector<word>& ws) const;

      BigInt mul(const BigInt& x, const BigInt& y, secure_vector<word>& ws) const;

      BigInt mul(const BigInt& x, std::span<const word> y, secure_vector<word>& ws) const;

      void mul_by(BigInt& x, std::span<const word> y, secure_vector<word>& ws) const;

      void mul_by(BigInt& x, const BigInt& y, secure_vector<word>& ws) const;

      BigInt sqr(const BigInt& x, secure_vector<word>& ws) const;

      BigInt sqr(std::span<const word> x, secure_vector<word>& ws) const;

      void sqr(BigInt& z, const BigInt& x, secure_vector<word>& ws) const;

      void sqr(BigInt& z, std::span<const word> x, secure_vector<word>& ws) const;

      void square_this(BigInt& x, secure_vector<word>& ws) const;

   private:
      BigInt m_p;
      BigInt m_r1;
      BigInt m_r2;
      BigInt m_r3;
      word m_p_dash;
      size_t m_p_words;
};

}  // namespace Botan

#endif
