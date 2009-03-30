/*
* Default Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_DEFAULT_ENGINE_H__
#define BOTAN_DEFAULT_ENGINE_H__

#include <botan/engine.h>

namespace Botan {

/*
* Default Engine
*/
class BOTAN_DLL Default_Engine : public Engine
   {
   public:
      std::string provider_name() const { return "core"; }

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

#if defined(BOTAN_HAS_ECDSA)
      virtual ECDSA_Operation* ecdsa_op(const EC_Domain_Params&,
                                        const BigInt&,
                                        const PointGFp&) const;
#endif

#if defined(BOTAN_HAS_ECKAEG)
      virtual ECKAEG_Operation* eckaeg_op(const EC_Domain_Params&,
                                          const BigInt&,
                                          const PointGFp&) const;
#endif

      Modular_Exponentiator* mod_exp(const BigInt&,
                                     Power_Mod::Usage_Hints) const;

      virtual bool can_add_algorithms() { return true; }

      Keyed_Filter* get_cipher(const std::string&, Cipher_Dir,
                               Algorithm_Factory&);

   private:
      BlockCipher* find_block_cipher(const SCAN_Name&,
                                     Algorithm_Factory&) const;

      StreamCipher* find_stream_cipher(const SCAN_Name&,
                                       Algorithm_Factory&) const;

      HashFunction* find_hash(const SCAN_Name& reqeust,
                              Algorithm_Factory&) const;

      MessageAuthenticationCode* find_mac(const SCAN_Name& reqeust,
                                          Algorithm_Factory&) const;
   };

}

#endif
