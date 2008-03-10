/*************************************************
* AEP Engine Header File                         *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_EXT_AEP_ENGINE_H__
#define BOTAN_EXT_AEP_ENGINE_H__

#include <botan/engine.h>
#include <vector>

namespace Botan {

/*************************************************
* AEP Engine                                     *
*************************************************/
class AEP_Engine : public Engine
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

      static BigInt pow_mod(const BigInt&, const BigInt&, const BigInt&);

      static BigInt pow_mod_crt(const BigInt&, const BigInt&, const BigInt&,
                                const BigInt&, const BigInt&, const BigInt&,
                                const BigInt&);

      static u32bit get_entropy(byte[], u32bit) throw();
      static bool ok_to_use(const BigInt&) throw();

      AEP_Engine();
      ~AEP_Engine();
   private:
      static bool daemon_is_up;
   };

}

#endif
