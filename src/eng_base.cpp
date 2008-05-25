/*************************************************
* Basic No-Op Engine Source File                 *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/engine.h>
#include <botan/libstate.h>
#include <botan/stl_util.h>
#include <botan/lookup.h>
#include <iostream>



using namespace Botan::math::ec;

namespace Botan {

namespace {

/*************************************************
* Algorithm Cache                                *
*************************************************/
template<typename T>
class Algorithm_Cache_Impl : public Engine::Algorithm_Cache<T>
   {
   public:
	 std::tr1::shared_ptr<T> get(const std::string& name) const
         {
         Mutex_Holder lock(mutex);
         return search_map(mappings, name);
         }

      void add(std::tr1::shared_ptr<T> const& algo, const std::string& index_name = "") const
         {
         if(!algo)
            return;

         Mutex_Holder lock(mutex);

         const std::string name =
           (index_name != "" ? index_name : algo->name());

         if(mappings.find(name) != mappings.end())
            mappings[name].reset();
         mappings[name] = algo;
         }

      Algorithm_Cache_Impl()
         {
         mutex = std::tr1::shared_ptr<Mutex>(global_state().get_mutex().release());
         }

      ~Algorithm_Cache_Impl()
         {
         }
   private:
      std::tr1::shared_ptr<Mutex> mutex;
      mutable std::map<std::string, std::tr1::shared_ptr<T> > mappings;
   };


}

/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
std::tr1::shared_ptr<IF_Operation> Engine::if_op(const BigInt&, const BigInt&, const BigInt&,
                            const BigInt&, const BigInt&, const BigInt&,
                            const BigInt&, const BigInt&) const
   {
   return std::tr1::shared_ptr<IF_Operation>();
   }

/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
/*
DSA_Operation* Engine::dsa_op(const DL_Group&, const BigInt&,
                              const BigInt&) const
   {
   return 0;
   }
*/
/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
/*
NR_Operation* Engine::nr_op(const DL_Group&, const BigInt&,
                            const BigInt&) const
   {
   return 0;
   }
*/
/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
/*
ELG_Operation* Engine::elg_op(const DL_Group&, const BigInt&,
                              const BigInt&) const
   {
   return 0;
   }
*/
/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
std::tr1::shared_ptr<DH_Operation> Engine::dh_op(const DL_Group&, const BigInt&) const
   {
   return std::tr1::shared_ptr<DH_Operation>();
   }

/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
std::tr1::shared_ptr<ECDSA_Operation>
    Engine::ecdsa_op(EC_Domain_Params const&, BigInt const&, PointGFp const&) const
    {
    return std::tr1::shared_ptr<ECDSA_Operation>();
    }
/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
std::tr1::shared_ptr<ECKAEG_Operation>
   Engine::eckaeg_op(EC_Domain_Params const&, BigInt const& , PointGFp const& ) const
   {
   return std::tr1::shared_ptr<ECKAEG_Operation>();
   }
/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
std::auto_ptr<Modular_Exponentiator> Engine::mod_exp(const BigInt&,
                                       Power_Mod::Usage_Hints) const
   {
   return std::auto_ptr<Modular_Exponentiator>();
   }

/*************************************************
* Acquire a BlockCipher                          *
*************************************************/
std::tr1::shared_ptr<BlockCipher const> Engine::block_cipher(const std::string& name) const
   {
   return lookup_algo(cache_of_bc, deref_alias(name),
                      this, &Engine::find_block_cipher);
   }

/*************************************************
* Acquire a StreamCipher                         *
*************************************************/
std::tr1::shared_ptr<StreamCipher const> Engine::stream_cipher(const std::string& name) const
   {
   return lookup_algo(cache_of_sc, deref_alias(name),
                      this, &Engine::find_stream_cipher);
   }

/*************************************************
* Acquire a HashFunction                         *
*************************************************/
std::tr1::shared_ptr<HashFunction const>  Engine::hash(const std::string& name) const
   {
   return lookup_algo(cache_of_hf, deref_alias(name),
                      this, &Engine::find_hash);
   }

/*************************************************
* Acquire a MessageAuthenticationCode            *
*************************************************/
std::tr1::shared_ptr<MessageAuthenticationCode const> Engine::mac(const std::string& name) const
   {
   return lookup_algo(cache_of_mac, deref_alias(name),
                      this, &Engine::find_mac);
   }

/*************************************************
* Acquire a S2K object                           *
*************************************************/

std::tr1::shared_ptr<S2K const> Engine::s2k(const std::string& name) const
   {
   return lookup_algo(cache_of_s2k, deref_alias(name),
                      this, &Engine::find_s2k);
   }

/*************************************************
* Acquire a cipher padding object                *
*************************************************/
std::tr1::shared_ptr<BlockCipherModePaddingMethod const>
Engine::bc_pad(const std::string& name) const
   {
   return lookup_algo(cache_of_bc_pad, deref_alias(name),
                      this, &Engine::find_bc_pad);
   }

/*************************************************
* Add a block cipher to the lookup table         *
*************************************************/
void Engine::add_algorithm_bc(SharedPtrConverter<BlockCipher> const& algo) const
   {
   cache_of_bc->add(algo.get_shared());
   }

/*************************************************
* Add a stream cipher to the lookup table        *
*************************************************/
void Engine::add_algorithm_sc(SharedPtrConverter<StreamCipher> const& algo) const
   {
   cache_of_sc->add(algo.get_shared());
   }

/*************************************************
* Add a hash function to the lookup table        *
*************************************************/
void Engine::add_algorithm_hf(SharedPtrConverter<HashFunction> const& algo) const
   {
   cache_of_hf->add(algo.get_shared());
   }

/*************************************************
* Add a MAC to the lookup table                  *
*************************************************/
void Engine::add_algorithm_mac(SharedPtrConverter<MessageAuthenticationCode> const& algo) const
   {
   cache_of_mac->add(algo.get_shared());
   }

/*************************************************
* Add a S2K to the lookup table                  *
*************************************************/
void Engine::add_algorithm_s2k(SharedPtrConverter<S2K> const& algo) const
   {
   cache_of_s2k->add(algo.get_shared());
   }
/*************************************************
* Add a cipher pad method to the lookup table    *
*************************************************/
void Engine::add_algorithm_bcmpm(SharedPtrConverter<BlockCipherModePaddingMethod> const& algo) const
   {
   cache_of_bc_pad->add(algo.get_shared());
   }

/*************************************************
* Create an Engine                               *
*************************************************/
Engine::Engine()
   {
   cache_of_bc = std::tr1::shared_ptr<Algorithm_Cache_Impl<BlockCipher> >(new Algorithm_Cache_Impl<BlockCipher>());
   cache_of_sc = std::tr1::shared_ptr<Algorithm_Cache_Impl<StreamCipher> >(new Algorithm_Cache_Impl<StreamCipher>());
   cache_of_hf = std::tr1::shared_ptr<Algorithm_Cache_Impl<HashFunction> >(new Algorithm_Cache_Impl<HashFunction>());
   cache_of_mac = std::tr1::shared_ptr<Algorithm_Cache_Impl<MessageAuthenticationCode> >(
			   new Algorithm_Cache_Impl<MessageAuthenticationCode>());
   cache_of_s2k = std::tr1::shared_ptr<Algorithm_Cache_Impl<S2K> >(new Algorithm_Cache_Impl<S2K>());
   cache_of_bc_pad = std::tr1::shared_ptr<Algorithm_Cache_Impl<BlockCipherModePaddingMethod> >(
			   new Algorithm_Cache_Impl<BlockCipherModePaddingMethod>());
   }

/*************************************************
* Destroy an Engine                              *
*************************************************/
Engine::~Engine()
   {

   }

/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
std::tr1::shared_ptr<BlockCipher> Engine::find_block_cipher(const std::string&) const
   {
   return std::tr1::shared_ptr<BlockCipher>();
   }

/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
std::tr1::shared_ptr<StreamCipher> Engine::find_stream_cipher(const std::string&) const
   {
   return std::tr1::shared_ptr<StreamCipher>();
   }

/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
std::tr1::shared_ptr<HashFunction> Engine::find_hash(const std::string&) const
   {
   return std::tr1::shared_ptr<HashFunction>();
   }

/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
std::tr1::shared_ptr<MessageAuthenticationCode> Engine::find_mac(const std::string&) const
   {
   return std::tr1::shared_ptr<MessageAuthenticationCode>();
   }

/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
std::tr1::shared_ptr<S2K> Engine::find_s2k(const std::string&) const
   {
   return std::tr1::shared_ptr<S2K>();
   }
/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
std::tr1::shared_ptr<BlockCipherModePaddingMethod> Engine::find_bc_pad(const std::string&) const
   {
   return std::tr1::shared_ptr<BlockCipherModePaddingMethod>();
   }

/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
std::tr1::shared_ptr<Keyed_Filter> Engine::get_cipher(const std::string&, Cipher_Dir)
   {
   return std::tr1::shared_ptr<Keyed_Filter>();
   }

}
