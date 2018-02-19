/*
* Discrete Logarithm Group
* (C) 1999-2008,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DL_PARAM_H_
#define BOTAN_DL_PARAM_H_

#include <botan/bigint.h>

namespace Botan {

class DL_Group_Data;

/**
* This class represents discrete logarithm groups. It holds a prime
* modulus p, a generator g, and (optionally) a prime q which is a
* factor of (p-1). In most cases g generates the order-q subgroup.
*/
class BOTAN_PUBLIC_API(2,0) DL_Group final
   {
   public:
      /**
      * Determine the prime creation for DL groups.
      */
      enum PrimeType { Strong, Prime_Subgroup, DSA_Kosherizer };

      /**
      * The DL group encoding format variants.
      */
      enum Format {
         ANSI_X9_42,
         ANSI_X9_57,
         PKCS_3,

         DSA_PARAMETERS = ANSI_X9_57,
         DH_PARAMETERS = ANSI_X9_42,
         ANSI_X9_42_DH_PARAMETERS = ANSI_X9_42,
         PKCS3_DH_PARAMETERS = PKCS_3
      };

      /**
      * Construct a DL group with uninitialized internal value.
      * Use this constructor is you wish to set the groups values
      * from a DER or PEM encoded group.
      */
      DL_Group() = default;

      /**
      * Construct a DL group that is registered in the configuration.
      * @param name the name that is configured in the global configuration
      * for the desired group. If no configuration file is specified,
      * the default values from the file policy.cpp will be used. For instance,
      * use "modp/ietf/3072".
      */
      DL_Group(const std::string& name);

      /**
      * Create a new group randomly.
      * @param rng the random number generator to use
      * @param type specifies how the creation of primes p and q shall
      * be performed. If type=Strong, then p will be determined as a
      * safe prime, and q will be chosen as (p-1)/2. If
      * type=Prime_Subgroup and qbits = 0, then the size of q will be
      * determined according to the estimated difficulty of the DL
      * problem. If type=DSA_Kosherizer, DSA primes will be created.
      * @param pbits the number of bits of p
      * @param qbits the number of bits of q. Leave it as 0 to have
      * the value determined according to pbits.
      */
      DL_Group(RandomNumberGenerator& rng, PrimeType type,
               size_t pbits, size_t qbits = 0);

      /**
      * Create a DSA group with a given seed.
      * @param rng the random number generator to use
      * @param seed the seed to use to create the random primes
      * @param pbits the desired bit size of the prime p
      * @param qbits the desired bit size of the prime q.
      */
      DL_Group(RandomNumberGenerator& rng,
               const std::vector<uint8_t>& seed,
               size_t pbits = 1024, size_t qbits = 0);

      /**
      * Create a DL group.
      * @param p the prime p
      * @param g the base g
      */
      DL_Group(const BigInt& p, const BigInt& g);

      /**
      * Create a DL group.
      * @param p the prime p
      * @param q the prime q
      * @param g the base g
      */
      DL_Group(const BigInt& p, const BigInt& q, const BigInt& g);

      /**
      * Decode a BER-encoded DL group param
      */
      DL_Group(const uint8_t ber[], size_t ber_len, Format format);

      /**
      * Decode a BER-encoded DL group param
      */
      template<typename Alloc>
      DL_Group(const std::vector<uint8_t, Alloc>& ber, Format format) :
         DL_Group(ber.data(), ber.size(), format) {}

      /**
      * Get the prime p.
      * @return prime p
      */
      const BigInt& get_p() const;

      /**
      * Get the prime q, returns zero if q is not used
      * @return prime q
      */
      const BigInt& get_q() const;

      /**
      * Get the base g.
      * @return base g
      */
      const BigInt& get_g() const;

      /**
      * Perform validity checks on the group.
      * @param rng the rng to use
      * @param strong whether to perform stronger by lengthier tests
      * @return true if the object is consistent, false otherwise
      */
      bool verify_group(RandomNumberGenerator& rng, bool strong) const;

      /**
      * Encode this group into a string using PEM encoding.
      * @param format the encoding format
      * @return string holding the PEM encoded group
      */
      std::string PEM_encode(Format format) const;

      /**
      * Encode this group into a string using DER encoding.
      * @param format the encoding format
      * @return string holding the DER encoded group
      */
      std::vector<uint8_t> DER_encode(Format format) const;

      /*
      * Reduce an integer modulo p
      * @return x % p
      */
      BigInt mod_p(const BigInt& x) const;

      /*
      * Multiply and reduce an integer modulo p
      * @return (x*y) % p
      */
      BigInt multiply_mod_p(const BigInt& x, const BigInt& y) const;

      BigInt inverse_mod_p(const BigInt& x) const;

      /*
      * Modular exponentiation
      * @return (g^x) % p
      */
      BigInt power_g_p(const BigInt& x) const;

      /**
      * Return the size of p in bits
      * Same as get_p().bits()
      */
      size_t p_bits() const;

      /**
      * Return the size of p in bytes
      * Same as get_p().bytes()
      */
      size_t p_bytes() const;

      /**
      * Decode a DER/BER encoded group into this instance.
      * @param ber a vector containing the DER/BER encoded group
      * @param format the format of the encoded group
      */
      void BER_decode(const std::vector<uint8_t>& ber, Format format);

      /**
      * Decode a PEM encoded group into this instance.
      * @param pem the PEM encoding of the group
      */
      void PEM_decode(const std::string& pem);

      /**
      * Return PEM representation of named DL group
      */
      static std::string BOTAN_DEPRECATED("Use DL_Group(name).PEM_encode()")
         PEM_for_named_group(const std::string& name);

      /*
      * For internal use only
      */
      static std::shared_ptr<DL_Group_Data> DL_group_info(const std::string& name);

   private:
      static std::shared_ptr<DL_Group_Data> load_DL_group_info(const char* p_str,
                                                               const char* q_str,
                                                               const char* g_str);

      static std::shared_ptr<DL_Group_Data> load_DL_group_info(const char* p_str,
                                                               const char* g_str);

      static std::shared_ptr<DL_Group_Data>
         BER_decode_DL_group(const uint8_t data[], size_t data_len, DL_Group::Format format);

      const DL_Group_Data& data() const;
      std::shared_ptr<DL_Group_Data> m_data;
   };

}

#endif
