/*************************************************
* Engine Header File                             *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_ENGINE_H__
#define BOTAN_ENGINE_H__

#include <botan/base.h>
#include <botan/mutex.h>
#include <botan/pow_mod.h>
#include <botan/basefilt.h>
#include <botan/enums.h>

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
  #include <botan/ecc_op.h>
  #include <botan/ec_dompar.h>
#endif

#include <utility>
#include <map>

namespace Botan {

/*************************************************
* Engine Base Class                              *
*************************************************/
class BOTAN_DLL Engine
   {
   public:
      template<typename T>
      class BOTAN_DLL Algorithm_Cache
         {
         public:
            virtual T* get(const std::string&) const = 0;
            virtual void add(T* algo, const std::string& = "") const = 0;
            virtual ~Algorithm_Cache() {}
         };

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

      virtual ECKAEG_Operation* eckaeg_op(const EC_Domain_Params&,
                                          const BigInt&,
                                          const PointGFp&) const
         { return 0; }
#endif

      virtual Modular_Exponentiator* mod_exp(const BigInt&,
                                             Power_Mod::Usage_Hints) const
         { return 0; }

      virtual Keyed_Filter* get_cipher(const std::string&, Cipher_Dir);

      const BlockCipher* block_cipher(const std::string&) const;
      const StreamCipher* stream_cipher(const std::string&) const;
      const HashFunction* hash(const std::string&) const;
      const MessageAuthenticationCode* mac(const std::string&) const;
      const class S2K* s2k(const std::string&) const;
      const class BlockCipherModePaddingMethod*
         bc_pad(const std::string&) const;

      void add_algorithm(BlockCipher*) const;
      void add_algorithm(StreamCipher*) const;
      void add_algorithm(HashFunction*) const;
      void add_algorithm(MessageAuthenticationCode*) const;
      void add_algorithm(class S2K*) const;
      void add_algorithm(class BlockCipherModePaddingMethod*) const;

      Engine();
      virtual ~Engine();
   private:
      virtual BlockCipher* find_block_cipher(const std::string&) const;
      virtual StreamCipher* find_stream_cipher(const std::string&) const;
      virtual HashFunction* find_hash(const std::string&) const;
      virtual MessageAuthenticationCode* find_mac(const std::string&) const;
      virtual class S2K* find_s2k(const std::string&) const;
      virtual class BlockCipherModePaddingMethod*
         find_bc_pad(const std::string&) const;

      template<typename T>
      const T* lookup_algo(const Algorithm_Cache<T>* cache,
                           const std::string& name,
                           const Engine* engine,
                           T* (Engine::*find)(const std::string&) const) const
         {
         T* algo = cache->get(name);
         if(!algo)
            {
            algo = (engine->*find)(name);
            if(algo)
               cache->add(algo, name);
            }
         return algo;
         }

      Algorithm_Cache<BlockCipher>* cache_of_bc;
      Algorithm_Cache<StreamCipher>* cache_of_sc;
      Algorithm_Cache<HashFunction>* cache_of_hf;
      Algorithm_Cache<MessageAuthenticationCode>* cache_of_mac;
      Algorithm_Cache<BlockCipherModePaddingMethod>* cache_of_bc_pad;
      Algorithm_Cache<S2K>* cache_of_s2k;
   };

namespace Engine_Core {

/*************************************************
* Get an operation from an Engine                *
*************************************************/
Modular_Exponentiator* mod_exp(const BigInt&, Power_Mod::Usage_Hints);

#if defined(BOTAN_HAS_IF_PUBLIC_KEY_FAMILY)
IF_Operation* if_op(const BigInt&, const BigInt&, const BigInt&,
                    const BigInt&, const BigInt&, const BigInt&,
                    const BigInt&, const BigInt&);
#endif

#if defined(BOTAN_HAS_DSA)
DSA_Operation* dsa_op(const DL_Group&, const BigInt&, const BigInt&);
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
NR_Operation* nr_op(const DL_Group&, const BigInt&, const BigInt&);
#endif

#if defined(BOTAN_HAS_ELGAMAL)
ELG_Operation* elg_op(const DL_Group&, const BigInt&, const BigInt&);
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
DH_Operation* dh_op(const DL_Group&, const BigInt&);
#endif

#if defined(BOTAN_HAS_ECDSA)
ECDSA_Operation* ecdsa_op(const EC_Domain_Params& dom_pars,
                          const BigInt& priv_key,
                          const PointGFp& pub_key);

ECKAEG_Operation* eckaeg_op(const EC_Domain_Params& dom_pars,
                            const BigInt& priv_key,
                            const PointGFp& pub_key);
#endif

}

}

#endif
