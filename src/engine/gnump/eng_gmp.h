/*
* GMP Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ENGINE_GMP_H__
#define BOTAN_ENGINE_GMP_H__

#include <botan/engine.h>

namespace Botan {

/*
* GMP Engine
*/
class BOTAN_DLL GMP_Engine : public Engine
   {
   public:
      std::string provider_name() const { return "gmp"; }

#if defined(BOTAN_HAS_IF_PUBLIC_KEY_FAMILY)
      IF_Operation* if_op(const BigInt&, const BigInt&, const BigInt&,
                          const BigInt&, const BigInt&, const BigInt&,
                          const BigInt&, const BigInt&) const;
#endif

#if defined(BOTAN_HAS_DSA)
      DSA_Operation* dsa_op(const DL_Group&, const BigInt&,
                            const BigInt&) const;
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
      NR_Operation* nr_op(const DL_Group&, const BigInt&, const BigInt&) const;
#endif

#if defined(BOTAN_HAS_ELGAMAL)
      ELG_Operation* elg_op(const DL_Group&, const BigInt&,
                            const BigInt&) const;
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
      DH_Operation* dh_op(const DL_Group&, const BigInt&) const;
#endif

      Modular_Exponentiator* mod_exp(const BigInt&,
                                     Power_Mod::Usage_Hints) const;

      GMP_Engine();
   private:
      static void set_memory_hooks();
   };

}

#endif
