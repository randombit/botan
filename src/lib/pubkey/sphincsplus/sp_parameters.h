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

enum class Sphincs_Hash_Instance
   {
   Shake256,
   Sha256,
   Haraka
   };

class Sphincs_Parameters
   {
   public:
      Sphincs_Hash_Instance hash() const { return m_hash_instance; }

      /**
       * @returns the algorithm specifier of the hash function to be used
       */
      std::string hash_name() const
         {
         switch(m_hash_instance)
            {
            case Sphincs_Hash_Instance::Shake256:
               return "SHAKE-256(???)"; // TODO: fill this in!
            case Sphincs_Hash_Instance::Sha256:
               return "SHA-256";
            case Sphincs_Hash_Instance::Haraka:
               throw Not_Implemented("Haraka is currently not supported");
            }
         Botan::unreachable();
         }

      /**
       * @returns SPHINCS+ security parameter in bytes
       */
      size_t n() const { return m_n; }

      /**
       * @returns Number of FORS trees to use
       */
      size_t k() const { return m_k; }

      /**
       * This is the desired height of the FORS trees, aka `log(t)` with t being
       * the number of leaves in each FORS tree.
       *
       * @returns Height of the FORS trees
       */
      size_t a() const { return m_a; }

      /**
       * @returns Height of the SPHINCS+ hypertree
       */
      size_t h() const { return m_h; }

      /**
       * @returns Number of XMSS layers in the SPHINCS+ hypertree
       */
      size_t d() const { return m_d; }

      /**
       * @returns the Winternitz parameter for WOTS+ signatures
       */
      size_t w() const { return m_w; }

   private:
      Sphincs_Hash_Instance m_hash_instance;
      size_t m_k;
      size_t m_a;
      size_t m_h;
      size_t m_d;
      size_t m_w;
      size_t m_n;
   };

}

#endif
