/*
 * SPHINCS+ Parameters
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_SP_PARAMS_H_
#define BOTAN_SP_PARAMS_H_

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/secmem.h>
#include <botan/strong_type.h>
#include <botan/internal/sp_address.h>

#include <memory>

namespace Botan {

enum class Sphincs_Hash_Type
   {
   Shake256,
   Sha256,
   Haraka,
   };

enum class Sphincs_Parameter_Set
   {
   Sphincs128Small,
   Sphincs128Fast,
   Sphincs192Small,
   Sphincs192Fast,
   Sphincs256Small,
   Sphincs256Fast,
   };

class Sphincs_Parameters
   {
   private:
      static Sphincs_Hash_Type hash_from_name(std::string_view name);
      static Sphincs_Parameter_Set set_from_name(std::string_view name);

   public:
      static Sphincs_Parameters create(Sphincs_Parameter_Set set, Sphincs_Hash_Type hash)
         {
         // See "Table 3" in SPHINCS+ specification (NIST R3.1 submission, page 39)
         switch(set)
            {
            case Sphincs_Parameter_Set::Sphincs128Small:
               return Sphincs_Parameters(set, hash, 16, 63, 7, 12, 14, 16);
            case Sphincs_Parameter_Set::Sphincs128Fast:
               return Sphincs_Parameters(set, hash, 16, 66, 22, 6, 33, 16);

            case Sphincs_Parameter_Set::Sphincs192Small:
               return Sphincs_Parameters(set, hash, 24, 63, 7, 14, 17, 16);
            case Sphincs_Parameter_Set::Sphincs192Fast:
               return Sphincs_Parameters(set, hash, 24, 66, 22, 8, 33, 16);

            case Sphincs_Parameter_Set::Sphincs256Small:
               return Sphincs_Parameters(set, hash, 32, 64, 8, 14, 22, 16);
            case Sphincs_Parameter_Set::Sphincs256Fast:
               return Sphincs_Parameters(set, hash, 32, 68, 17, 9, 35, 16);
            }

         Botan::unreachable();
         }

      static Sphincs_Parameters create(std::string_view name)
         {
         return Sphincs_Parameters::create(set_from_name(name), hash_from_name(name));
         }

      Sphincs_Hash_Type hash_type() const { return m_hash_type; }

      /**
       * @returns the algorithm specifier of the hash function to be used
       */
      std::string hash_name() const;

      /**
       * @returns SPHINCS+ security parameter in bytes
       */
      size_t n() const { return m_n; }

      /**
       * @returns Height of the SPHINCS+ hypertree
       */
      size_t h() const { return m_h; }

      /**
       * @returns Number of XMSS layers in the SPHINCS+ hypertree
       */
      size_t d() const { return m_d; }

      /**
       * This is the desired height of the FORS trees, aka `log(t)` with t being
       * the number of leaves in each FORS tree.
       *
       * @returns Height of the FORS trees
       */
      size_t a() const { return m_a; }

      /**
       * @returns Number of FORS trees to use
       */
      size_t k() const { return m_k; }

      /**
       * @returns the Winternitz parameter for WOTS+ signatures
       */
      size_t w() const { return m_w; }

   private:
      Sphincs_Parameters(Sphincs_Parameter_Set set, Sphincs_Hash_Type hash_type,
                        size_t n, size_t h, size_t d, size_t a, size_t k, size_t w)
         : m_set(set), m_hash_type(hash_type)
         , m_n(n), m_h(h), m_d(d), m_a(a), m_k(k), m_w(w) {}

   private:
      Sphincs_Parameter_Set m_set;
      Sphincs_Hash_Type m_hash_type;
      size_t m_n;
      size_t m_h;
      size_t m_d;
      size_t m_a;
      size_t m_k;
      size_t m_w;
   };

}

#endif
