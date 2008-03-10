/*************************************************
* Discrete Logarithm Group Header File           *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_DL_PARAM_H__
#define BOTAN_DL_PARAM_H__

#include <botan/bigint.h>
#include <botan/data_src.h>

namespace Botan {

/*************************************************
* Discrete Logarithm Group                       *
*************************************************/
class DL_Group
   {
   public:
      const BigInt& get_p() const;
      const BigInt& get_q() const;
      const BigInt& get_g() const;

      enum Format { ANSI_X9_42, ANSI_X9_57, PKCS_3 };
      enum PrimeType { Strong, Prime_Subgroup, DSA_Kosherizer };

      bool verify_group(bool) const;

      std::string PEM_encode(Format) const;
      SecureVector<byte> DER_encode(Format) const;
      void BER_decode(DataSource&, Format);
      void PEM_decode(DataSource&);

      DL_Group();
      DL_Group(const std::string&);
      DL_Group(PrimeType, u32bit, u32bit = 0);
      DL_Group(const MemoryRegion<byte>&, u32bit = 1024, u32bit = 0);
      DL_Group(const BigInt&, const BigInt&);
      DL_Group(const BigInt&, const BigInt&, const BigInt&);
   private:
      static BigInt make_dsa_generator(const BigInt&, const BigInt&);
      static SecureVector<byte> generate_dsa_primes(BigInt&, BigInt&,
                                                    u32bit, u32bit);
      static bool generate_dsa_primes(BigInt&, BigInt&, u32bit, u32bit,
                                      const MemoryRegion<byte>&);

      void init_check() const;
      void initialize(const BigInt&, const BigInt&, const BigInt&);
      bool initialized;
      BigInt p, q, g;
   };

}

#endif
