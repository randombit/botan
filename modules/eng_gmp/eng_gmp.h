/*************************************************
* GMP Engine Header File                         *
* (C) 1999-2008 The Botan Project                *
*************************************************/

#ifndef BOTAN_EXT_ENGINE_GMP_H__
#define BOTAN_EXT_ENGINE_GMP_H__

#include <botan/engine.h>

namespace Botan {

/*************************************************
* GMP Engine                                     *
*************************************************/
class GMP_Engine : public Engine
   {
   public:
      IF_Operation* if_op(const BigInt&, const BigInt&, const BigInt&,
                          const BigInt&, const BigInt&, const BigInt&,
                          const BigInt&, const BigInt&) const;

      DSA_Operation* dsa_op(const DL_Group&, const BigInt&,
                            const BigInt&) const;

      NR_Operation* nr_op(const DL_Group&, const BigInt&, const BigInt&) const;

      ELG_Operation* elg_op(const DL_Group&, const BigInt&,
                            const BigInt&) const;

      DH_Operation* dh_op(const DL_Group&, const BigInt&) const;

      Modular_Exponentiator* mod_exp(const BigInt&,
                                     Power_Mod::Usage_Hints) const;

      GMP_Engine();
   private:
      static void set_memory_hooks();
   };

}

#endif
