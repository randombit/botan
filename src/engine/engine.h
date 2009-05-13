/*
* Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ENGINE_H__
#define BOTAN_ENGINE_H__

#include <botan/scan_name.h>

#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/pow_mod.h>

#include <utility>
#include <map>

#if defined(BOTAN_HAS_IF_PUBLIC_KEY_FAMILY)
  #include <botan/if_op.h>
#endif

#if defined(BOTAN_HAS_DSA)
  #include <botan/dsa_op.h>
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
  #include <botan/dh_op.h>
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
  #include <botan/nr_op.h>
#endif

#if defined(BOTAN_HAS_ELGAMAL)
  #include <botan/elg_op.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ecdsa_op.h>
  #include <botan/ec_dompar.h>
#endif

#if defined(BOTAN_HAS_ECKAEG)
  #include <botan/eckaeg_op.h>
  #include <botan/ec_dompar.h>
#endif

namespace Botan {

class Algorithm_Factory;
class Keyed_Filter;

/*
* Engine Base Class
*/
class BOTAN_DLL Engine
   {
   public:
      virtual ~Engine() {}

      virtual std::string provider_name() const = 0;

      // Lookup functions
      virtual BlockCipher*
         find_block_cipher(const SCAN_Name&, Algorithm_Factory&) const
         { return 0; }

      virtual StreamCipher*
         find_stream_cipher(const SCAN_Name&, Algorithm_Factory&) const
         { return 0; }

      virtual HashFunction*
         find_hash(const SCAN_Name&, Algorithm_Factory&) const
         { return 0; }

      virtual MessageAuthenticationCode*
         find_mac(const SCAN_Name&, Algorithm_Factory&) const
         { return 0; }

      virtual Modular_Exponentiator*
         mod_exp(const BigInt&, Power_Mod::Usage_Hints) const
         { return 0; }

      virtual Keyed_Filter* get_cipher(const std::string&,
                                       Cipher_Dir,
                                       Algorithm_Factory&)
         { return 0; }

#if defined(BOTAN_HAS_IF_PUBLIC_KEY_FAMILY)
      virtual IF_Operation* if_op(const BigInt&, const BigInt&, const BigInt&,
                                  const BigInt&, const BigInt&, const BigInt&,
                                  const BigInt&, const BigInt&) const
         { return 0; }
#endif

#if defined(BOTAN_HAS_DSA)
      virtual DSA_Operation* dsa_op(const DL_Group&, const BigInt&,
                                    const BigInt&) const
         { return 0; }
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
      virtual NR_Operation* nr_op(const DL_Group&, const BigInt&,
                                  const BigInt&) const
         { return 0; }
#endif

#if defined(BOTAN_HAS_ELGAMAL)
      virtual ELG_Operation* elg_op(const DL_Group&, const BigInt&,
                                    const BigInt&) const
         { return 0; }
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
      virtual DH_Operation* dh_op(const DL_Group&, const BigInt&) const
         { return 0; }
#endif

#if defined(BOTAN_HAS_ECDSA)
      virtual ECDSA_Operation* ecdsa_op(const EC_Domain_Params&,
                                        const BigInt&,
                                        const PointGFp&) const
         { return 0; }
#endif

#if defined(BOTAN_HAS_ECKAEG)
      virtual ECKAEG_Operation* eckaeg_op(const EC_Domain_Params&,
                                          const BigInt&,
                                          const PointGFp&) const
         { return 0; }
#endif
   };

}

#endif
