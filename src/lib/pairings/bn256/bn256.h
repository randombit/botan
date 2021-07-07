/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BN256_PAIRING_H_
#define BOTAN_BN256_PAIRING_H_

#include <botan/types.h>
#include <memory>
#include <vector>

namespace Botan {

class BigInt;

class BN_256_G1_Data;
class BN_256_G2_Data;
class BN_256_GT_Data;

/**
* BN_256 parameters
*/
#if 0
class BOTAN_UNSTABLE_API BN_256_Params final : public Pairing_Params
   {
   public:
      std::shared_ptr<const Montgomery_Params> monty_params() const;

      const BigInt& order() const;

      const GFp1& g1_curve_B() const;
      const GFp2& g2_curve_B() const;

      const GFp2& xi() const;
      const std::vector<GFp2>& xi1() const;
      const std::vector<GFp2>& xi2() const;

      std::vector<int8_t> naf_6u_p_2() const;

      uint64_t get_u() const;

      std::shared_ptr<G1_Data> generator_g1() const;
      std::shared_ptr<G2_Data> generator_g2() const;
   };
#endif

/**
* BN-256 curve compatible with dclxvi and Golang's bn256
*/
class BOTAN_UNSTABLE_API BN_256 final
   {
   public:
      class BOTAN_UNSTABLE_API G1 final
         {
         public:
            std::vector<uint8_t> serialize() const;
            bool operator==(const G1& other) const;
            bool operator!=(const G1& other) const { return !(*this == other); }

            G1 operator*(const BigInt& k) const;
            G1 operator+(const G1& x) const;
            bool valid_element() const;

         private:
            friend BN_256;
            G1(std::shared_ptr<BN_256_G1_Data> data);
            std::shared_ptr<BN_256_G1_Data> m_data;
         };

      class BOTAN_UNSTABLE_API G2 final
         {
         public:
            std::vector<uint8_t> serialize() const;
            bool operator==(const G2& other) const;
            bool operator!=(const G2& other) const { return !(*this == other); }

            G2 operator*(const BigInt& k) const;
            G2 operator+(const G2& x) const;
            bool valid_element() const;

         private:
            friend BN_256;
            G2(std::shared_ptr<BN_256_G2_Data> data);
            std::shared_ptr<BN_256_G2_Data> m_data;
         };

      class BOTAN_UNSTABLE_API GT final
         {
         public:
            std::vector<uint8_t> serialize() const;
            bool operator==(const GT& other) const;
            bool operator!=(const GT& other) const { return !(*this == other); }

            GT operator*(const BigInt& k) const;
            GT operator+(const GT& x) const;
            bool valid_element() const;

         private:
            friend BN_256;
            GT(std::shared_ptr<BN_256_GT_Data> data);
            std::shared_ptr<BN_256_GT_Data> m_data;
         };

      BN_256();

      /**
      * The estimated security level of this curve.
      */
      size_t security_level() const { return 110; }

      /**
      * Return the order of the group
      */
      const BigInt& order() const;

      /**
      * Return the G1 generator
      */
      G1 g1_generator() const;

      /**
      * Return the G2 generator
      */
      G2 g2_generator() const;

      /**
      * The pairing operation (TODO document this better)
      */
      GT pairing(const G1& g1, const G2& g2) const;

      #if 0
      /**
      * Hash an input onto G1
      */
      G1 g1_hash(const uint8_t input[], size_t input_len) const;

      /**
      * Hash an input onto G2
      */
      G2 g2_hash(const uint8_t input[], size_t input_len) const;
      #endif

      /**
      * Deserialize a G1 input
      */
      G1 g1_deserialize(const uint8_t input[], size_t input_len) const;

      /**
      * Deserialize a G2 element
      */
      G2 g2_deserialize(const uint8_t input[], size_t input_len) const;

      /*
      * Helpers taking std::vectors instead of raw byte arrays
      */

      #if 0
      template<typename Alloc>
         G1 g1_hash(const std::vector<uint8_t, Alloc>& vec) const
         {
         return g1_hash(vec.data(), vec.size());
         }

      template<typename Alloc>
         G2 g2_hash(const std::vector<uint8_t, Alloc>& vec) const
         {
         return g2_hash(vec.data(), vec.size());
         }
      #endif

      // TODO hashing with string inputs

      template<typename Alloc>
         G1 g1_deserialize(const std::vector<uint8_t, Alloc>& vec) const
         {
         return g1_deserialize(vec.data(), vec.size());
         }

      template<typename Alloc>
         G2 g2_deserialize(const std::vector<uint8_t, Alloc>& vec) const
         {
         return g2_deserialize(vec.data(), vec.size());
         }

   private:
      BN_256::G1 m_g1_generator;
      BN_256::G2 m_g2_generator;
   };

}


#endif
