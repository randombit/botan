/*************************************************
* Default Engine Header File                     *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_DEFAULT_ENGINE_H__
#define BOTAN_DEFAULT_ENGINE_H__

#include <botan/engine.h>

namespace Botan {

/*************************************************
* Default Engine                                 *
*************************************************/
class Default_Engine : public Engine
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

      Keyed_Filter* get_cipher(const std::string&, Cipher_Dir);
   private:
      BlockCipher* find_block_cipher(const std::string&) const;
      StreamCipher* find_stream_cipher(const std::string&) const;
      HashFunction* find_hash(const std::string&) const;
      MessageAuthenticationCode* find_mac(const std::string&) const;

      class S2K* find_s2k(const std::string&) const;
      class BlockCipherModePaddingMethod*
         find_bc_pad(const std::string&) const;
   };

}

#endif
