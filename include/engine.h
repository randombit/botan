/*************************************************
* Engine Header File                             *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_ENGINE_H__
#define BOTAN_ENGINE_H__

#include <botan/base.h>
#include <botan/mutex.h>
#include <botan/pk_ops.h>
#include <botan/pow_mod.h>
#include <botan/basefilt.h>
#include <botan/enums.h>
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

      virtual IF_Operation* if_op(const BigInt&, const BigInt&, const BigInt&,
                                  const BigInt&, const BigInt&, const BigInt&,
                                  const BigInt&, const BigInt&) const;
      virtual DSA_Operation* dsa_op(const DL_Group&, const BigInt&,
                                    const BigInt&) const;
      virtual NR_Operation* nr_op(const DL_Group&, const BigInt&,
                                  const BigInt&) const;
      virtual ELG_Operation* elg_op(const DL_Group&, const BigInt&,
                                    const BigInt&) const;
      virtual DH_Operation* dh_op(const DL_Group&, const BigInt&) const;

      virtual Modular_Exponentiator* mod_exp(const BigInt&,
                                             Power_Mod::Usage_Hints) const;

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

IF_Operation* if_op(const BigInt&, const BigInt&, const BigInt&,
                    const BigInt&, const BigInt&, const BigInt&,
                    const BigInt&, const BigInt&);

DSA_Operation* dsa_op(const DL_Group&, const BigInt&, const BigInt&);
NR_Operation* nr_op(const DL_Group&, const BigInt&, const BigInt&);

ELG_Operation* elg_op(const DL_Group&, const BigInt&, const BigInt&);

DH_Operation* dh_op(const DL_Group&, const BigInt&);

}

}

#endif
