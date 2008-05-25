/*************************************************
* Engine Header File                             *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_ENGINE_H__
#define BOTAN_ENGINE_H__

#include <botan/base.h>
#include <botan/mutex.h>
#include <botan/pk_ops.h>
#include <botan/bigint/pow_mod.h>
#include <botan/basefilt.h>
#include <botan/enums.h>
#include <utility>
#include <map>
#include <botan/pointers.h>
#include <iostream>
#include <botan/ec_dompar.h>
#include <botan/ecdsa.h>
#include <botan/freestore.h>

namespace Botan {

class S2K;
class BlockCipherModePaddingMethod;
/*************************************************
* Engine Base Class                              *
*************************************************/
class Engine
   {
   public:
      typedef std::tr1::shared_ptr<Keyed_Filter> Keyed_Filter_Ptr;

      template<typename T>
      class Algorithm_Cache
         {
         public:
            virtual std::tr1::shared_ptr<T> get(const std::string&) const = 0;
            virtual void add(std::tr1::shared_ptr<T> const& algo, const std::string& = "") const = 0;
            virtual ~Algorithm_Cache() {}
         };

      virtual std::tr1::shared_ptr<IF_Operation>
		  if_op(const BigInt&, const BigInt&, const BigInt&,
               const BigInt&, const BigInt&, const BigInt&,
               const BigInt&, const BigInt&) const;

      virtual std::tr1::shared_ptr<DH_Operation>
         dh_op(const DL_Group&, const BigInt&) const;
      
      virtual std::tr1::shared_ptr<ECDSA_Operation>
		  ecdsa_op(EC_Domain_Params const& dom_pars, BigInt const& priv_key, Botan::math::ec::PointGFp const& pub_key) const;

      virtual std::tr1::shared_ptr<ECKAEG_Operation>
         eckaeg_op(EC_Domain_Params const& dom_pars, BigInt const& priv_key, Botan::math::ec::PointGFp const& pub_key) const;

      virtual std::auto_ptr<Modular_Exponentiator>
         mod_exp(const BigInt&, Power_Mod::Usage_Hints) const;

      virtual std::tr1::shared_ptr<Keyed_Filter>
         get_cipher(const std::string&, Cipher_Dir);

      std::tr1::shared_ptr<BlockCipher const>
         block_cipher(const std::string&) const;

      std::tr1::shared_ptr<StreamCipher const>
         stream_cipher(const std::string&) const;

      std::tr1::shared_ptr<HashFunction const>
         hash(const std::string&) const;

      std::tr1::shared_ptr<MessageAuthenticationCode const>
         mac(const std::string&) const;

      std::tr1::shared_ptr<S2K const>
        s2k(const std::string&) const;

      std::tr1::shared_ptr<BlockCipherModePaddingMethod const>
         bc_pad(const std::string&) const;

      void add_algorithm_bc(SharedPtrConverter<BlockCipher> const&) const;
      void add_algorithm_sc(SharedPtrConverter<StreamCipher> const&) const;
      void add_algorithm_hf(SharedPtrConverter<HashFunction> const&) const;
      void add_algorithm_mac(SharedPtrConverter<MessageAuthenticationCode> const&) const;
      void add_algorithm_s2k(SharedPtrConverter<class S2K> const&) const;
      void add_algorithm_bcmpm(SharedPtrConverter<class BlockCipherModePaddingMethod> const&) const;

      Engine();
      virtual ~Engine();
   private:
      virtual std::tr1::shared_ptr<BlockCipher>
         find_block_cipher(const std::string&) const;

      virtual std::tr1::shared_ptr<StreamCipher>
         find_stream_cipher(const std::string&) const;

      virtual std::tr1::shared_ptr<HashFunction>
         find_hash(const std::string&) const;

      virtual std::tr1::shared_ptr<MessageAuthenticationCode>
         find_mac(const std::string&) const;

      virtual std::tr1::shared_ptr<S2K>
         find_s2k(const std::string&) const;

      virtual std::tr1::shared_ptr<BlockCipherModePaddingMethod>
         find_bc_pad(const std::string&) const;

      template<typename T>
      std::tr1::shared_ptr<T>
         lookup_algo(const std::tr1::shared_ptr<Algorithm_Cache<T> >& cache,
                     const std::string& name,
                     const Engine* engine,
                     std::tr1::shared_ptr<T> (Engine::*find)(const std::string& name) const) const
         {
         std::tr1::shared_ptr<T> algo = cache->get(name);
         if(!algo.get()) {
            cache->add(algo = (engine->*find)(name));
         }
         return algo;
         }

      std::tr1::shared_ptr<Algorithm_Cache<BlockCipher> > cache_of_bc;
      std::tr1::shared_ptr<Algorithm_Cache<StreamCipher> > cache_of_sc;
      std::tr1::shared_ptr<Algorithm_Cache<HashFunction> > cache_of_hf;
      std::tr1::shared_ptr<Algorithm_Cache<MessageAuthenticationCode> > cache_of_mac;
      std::tr1::shared_ptr<Algorithm_Cache<BlockCipherModePaddingMethod> > cache_of_bc_pad;
      std::tr1::shared_ptr<Algorithm_Cache<S2K> > cache_of_s2k;
   };

namespace Engine_Core {

/*************************************************
* Get an operation from an Engine                *
*************************************************/
std::auto_ptr<Modular_Exponentiator> mod_exp(const BigInt&, Power_Mod::Usage_Hints);

std::tr1::shared_ptr<IF_Operation> if_op(const BigInt&, const BigInt&, const BigInt&,
                    const BigInt&, const BigInt&, const BigInt&,
                    const BigInt&, const BigInt&);

std::tr1::shared_ptr<DH_Operation> dh_op(const DL_Group&, const BigInt&);

std::tr1::shared_ptr<ECDSA_Operation> ecdsa_op(EC_Domain_Params const& dom_pars, BigInt const& priv_key, Botan::math::ec::PointGFp const& pub_key);
std::tr1::shared_ptr<ECKAEG_Operation> eckaeg_op(EC_Domain_Params const& dom_pars, BigInt const& priv_key, Botan::math::ec::PointGFp const& pub_key);
}

}

#endif
