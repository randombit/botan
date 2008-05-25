/*************************************************
* Number Theory Header File                      *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_NUMBTHRY_H__
#define BOTAN_NUMBTHRY_H__

#include <botan/bigint.h>
#include <botan/bigint/reducer.h>
#include <botan/bigint/pow_mod.h>
#include <botan/secmem.h>
#include <botan/types.h>
#include <botan/mp_types.h>

namespace Botan {
/*************************************************
* Fused Arithmetic Operations                    *
*************************************************/
BigInt mul_add(const BigInt&, const BigInt&, const BigInt&);
BigInt sub_mul(const BigInt&, const BigInt&, const BigInt&);

BigInt exlusive_or(const BigInt&, const BigInt&);

/*************************************************
* Number Theory Functions                        *
*************************************************/
inline BigInt abs(const BigInt& n) { return n.abs(); }

void divide(const BigInt&, const BigInt&, BigInt&, BigInt&);

BigInt gcd(const BigInt&, const BigInt&);
BigInt lcm(const BigInt&, const BigInt&);

BigInt square(const BigInt&);
BigInt inverse_mod(const BigInt&, const BigInt&);
s32bit jacobi(const BigInt&, const BigInt&);

BigInt power_mod(const BigInt&, const BigInt&, const BigInt&);

/**
     * from FlexiProvider:
     *------------------------------------------------------
     * Computes the square root of a BigInteger modulo a prime employing the
     * Shanks-Tonelli algorithm.
     *
     * @param a
     *                value out of which we extract the square root
     * @param p
     *                prime modulus that determines the underlying field
     * @return a number <code>b</code> such that b<sup>2</sup> = a (mod p)
     *         if <code>a</code> is a quadratic residue modulo <code>p</code>.
     * @throws NoQuadraticResidueException
     *                 if <code>a</code> is a quadratic non-residue modulo
     *                 <code>p</code>
     *-----------------------------------------------------------
     */
BigInt ressol(const BigInt& a, const BigInt& p);

/*************************************************
* Utility Functions                              *
*************************************************/
u32bit low_zero_bits(const BigInt&);

/*************************************************
* Primality Testing                              *
*************************************************/
bool check_prime(const BigInt&);
bool is_prime(const BigInt&);
bool verify_prime(const BigInt&);

s32bit simple_primality_tests(const BigInt&);
bool passes_mr_tests(const BigInt&, u32bit = 1);
bool run_primality_tests(const BigInt&, u32bit = 1);

/*************************************************
* Random Number Generation                       *
*************************************************/
BigInt random_integer(u32bit);
/**
    * returns a BigInt in the intervall [min, max-1]
    */
BigInt random_integer(const BigInt&, const BigInt&);
BigInt random_prime(u32bit, const BigInt& = 1, u32bit = 1, u32bit = 2);
BigInt random_safe_prime(u32bit);

/*************************************************
* Prime Numbers                                  *
*************************************************/
const u32bit PRIME_TABLE_SIZE = 6541;
const u32bit PRIME_PRODUCTS_TABLE_SIZE = 256;

extern const u16bit PRIMES[];
extern const u64bit PRIME_PRODUCTS[];

/*************************************************
* Miller-Rabin Primality Tester                  *
*************************************************/
class MillerRabin_Test
   {
   public:
      bool passes_test(const BigInt&);
      MillerRabin_Test(const BigInt&);
   private:
      BigInt n, r, n_minus_1;
      u32bit s;
      Fixed_Exponent_Power_Mod pow_mod;
      Modular_Reducer reducer;
   };


/**
*calculates r=2^n with r>m (r beeing as small as possible) for an odd modulus m
* no check for oddity is performed!
*/
BigInt montgm_calc_r_oddmod(const BigInt& odd_modulus);

/**
*calculates m' = -m^(-1) mod b
*/
BigInt montgm_calc_m_dash(const BigInt& r, const BigInt& modulus, const BigInt& r_inv);

/**
* transforms a given ordinary residue to an m-residue
* refer to cited paper for meaning of r and m
*/
BigInt montg_trf_to_mres(const BigInt& ord_res, const BigInt& r, const BigInt& m);

/**
* transforms an m-residue back to an ordinary residue
*/
BigInt montg_trf_to_ordres(const BigInt& m_res, const BigInt& m, const BigInt& r_inv);


/**
 * Montgomery multiplication for prime moduli.
 * calculates MonPro as defined in cited paper, i.e. returns c_bar = a_bar * b_bar * r^-1 mod m
 * using the SOS method.
 *
 * Montgomery Multiplication
 * Koc, Acar,Kaliski: "Analyzing and Comparing
 * Montgomery Multiplication Algorithms",
 * IEEE Micro, 16(3):26-33, June 1996
 *
 * @date 2007
 * @author Falko Strenzke / FlexSecure GmbH
 * @param result result of montgomery multiplication
 * @param a_bar = a * r
 * @param b_bar = b * r
 * @param m the modulus
 * @param m_dash m' with r * r^(-1) - m * m' = 1
 * @param r with r = 2^(s*w), where W = 2^w is the machine word size in bits, and s is
 *          the number of words in m
 */
    void montg_mult(BigInt& result, BigInt& a_bar, BigInt& b_bar, const BigInt& m, const BigInt& m_dash, const BigInt r);

    /**
    * performs Timing Attack secure modular multiplication
    * c = a * b mod m;
    * returns c.
    * @date 2008
    * @author Falko Strenzke / FlexSecure GmbH
    * @param a the operand a
    * @param b the operand b
    * @param m the modulus
    */
    BigInt const mod_mul_secure(BigInt const& a, BigInt const& b,
                                BigInt const& m);

}

#endif
