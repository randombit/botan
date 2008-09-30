/*************************************************
* Discrete Logarithm Group Header File           *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_DL_PARAM_H__
#define BOTAN_DL_PARAM_H__

#include <botan/bigint.h>
#include <botan/data_src.h>

namespace Botan {

/*************************************************
* Discrete Logarithm Group                       *
*************************************************/
class BOTAN_DLL DL_Group
   {
   public:
      static SecureVector<byte>
         generate_dsa_primes(RandomNumberGenerator& rng,
                             BigInt& p, BigInt& q,
                             u32bit pbits, u32bit qbits);

      static bool generate_dsa_primes(RandomNumberGenerator& rng,
                                      BigInt& p_out, BigInt& q_out,
                                      u32bit p_bits, u32bit q_bits,
                                      const MemoryRegion<byte>& seed);

      const BigInt& get_p() const;
      const BigInt& get_q() const;
      const BigInt& get_g() const;

      enum Format {
         ANSI_X9_42,
         ANSI_X9_57,
         PKCS_3,

         DSA_PARAMETERS = ANSI_X9_57,
         DH_PARAMETERS = ANSI_X9_42,
         X942_DH_PARAMETERS = ANSI_X9_42,
         PKCS3_DH_PARAMETERS = PKCS_3
      };

      enum PrimeType { Strong, Prime_Subgroup, DSA_Kosherizer };

      bool verify_group(RandomNumberGenerator& rng, bool) const;

      std::string PEM_encode(Format) const;
      SecureVector<byte> DER_encode(Format) const;
      void BER_decode(DataSource&, Format);
      void PEM_decode(DataSource&);

      DL_Group();
      DL_Group(const std::string&);

      DL_Group(RandomNumberGenerator& rng, PrimeType, u32bit, u32bit = 0);
      DL_Group(RandomNumberGenerator& rng, const MemoryRegion<byte>&,
               u32bit = 1024, u32bit = 0);

      DL_Group(const BigInt& p, const BigInt& g);
      DL_Group(const BigInt& p, const BigInt& g, const BigInt& q);
   private:
      static BigInt make_dsa_generator(const BigInt&, const BigInt&);

      void init_check() const;
      void initialize(const BigInt&, const BigInt&, const BigInt&);
      bool initialized;
      BigInt p, q, g;
   };

}

#endif
