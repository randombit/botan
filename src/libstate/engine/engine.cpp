/*************************************************
* Basic No-Op Engine Source File                 *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/engine.h>
#include <botan/libstate.h>
#include <botan/stl_util.h>
#include <botan/mode_pad.h>

namespace Botan {

namespace {

/*************************************************
* Algorithm Cache                                *
*************************************************/
template<typename T>
class Algorithm_Cache_Impl : public Engine::Algorithm_Cache<T>
   {
   public:
      T* get(const std::string& name) const
         {
         Mutex_Holder lock(mutex);
         return search_map(mappings, name);
         }

      void add(T* algo, const std::string& index_name = "") const
         {
         if(!algo)
            return;

         Mutex_Holder lock(mutex);

         const std::string name =
            (index_name != "" ? index_name : algo->name());

         if(mappings.find(name) != mappings.end())
            delete mappings[name];
         mappings[name] = algo;
         }

      Algorithm_Cache_Impl()
         {
         mutex = global_state().get_mutex();
         }

      ~Algorithm_Cache_Impl()
         {
         typename std::map<std::string, T*>::iterator i = mappings.begin();

         while(i != mappings.end())
            {
            delete i->second;
            ++i;
            }
         delete mutex;
         }
   private:
      Mutex* mutex;
      mutable std::map<std::string, T*> mappings;
   };

}

/*************************************************
* Acquire a BlockCipher                          *
*************************************************/
const BlockCipher* Engine::block_cipher(const std::string& name) const
   {
   return lookup_algo(cache_of_bc, global_state().deref_alias(name),
                      this, &Engine::find_block_cipher);
   }

/*************************************************
* Acquire a StreamCipher                         *
*************************************************/
const StreamCipher* Engine::stream_cipher(const std::string& name) const
   {
   return lookup_algo(cache_of_sc, global_state().deref_alias(name),
                      this, &Engine::find_stream_cipher);
   }

/*************************************************
* Acquire a HashFunction                         *
*************************************************/
const HashFunction* Engine::hash(const std::string& name) const
   {
   return lookup_algo(cache_of_hf, global_state().deref_alias(name),
                      this, &Engine::find_hash);
   }

/*************************************************
* Acquire a MessageAuthenticationCode            *
*************************************************/
const MessageAuthenticationCode* Engine::mac(const std::string& name) const
   {
   return lookup_algo(cache_of_mac, global_state().deref_alias(name),
                      this, &Engine::find_mac);
   }

/*************************************************
* Add a block cipher to the lookup table         *
*************************************************/
void Engine::add_algorithm(BlockCipher* algo) const
   {
   cache_of_bc->add(algo);
   }

/*************************************************
* Add a stream cipher to the lookup table        *
*************************************************/
void Engine::add_algorithm(StreamCipher* algo) const
   {
   cache_of_sc->add(algo);
   }

/*************************************************
* Add a hash function to the lookup table        *
*************************************************/
void Engine::add_algorithm(HashFunction* algo) const
   {
   cache_of_hf->add(algo);
   }

/*************************************************
* Add a MAC to the lookup table                  *
*************************************************/
void Engine::add_algorithm(MessageAuthenticationCode* algo) const
   {
   cache_of_mac->add(algo);
   }

/*************************************************
* Create an Engine                               *
*************************************************/
Engine::Engine()
   {
   cache_of_bc = new Algorithm_Cache_Impl<BlockCipher>();
   cache_of_sc = new Algorithm_Cache_Impl<StreamCipher>();
   cache_of_hf = new Algorithm_Cache_Impl<HashFunction>();
   cache_of_mac = new Algorithm_Cache_Impl<MessageAuthenticationCode>();
   }

/*************************************************
* Destroy an Engine                              *
*************************************************/
Engine::~Engine()
   {
   delete cache_of_bc;
   delete cache_of_sc;
   delete cache_of_hf;
   delete cache_of_mac;
   }

namespace Engine_Core {

#if defined(BOTAN_HAS_IF_PUBLIC_KEY_FAMILY)
/*************************************************
* Acquire an IF op                               *
*************************************************/
IF_Operation* if_op(const BigInt& e, const BigInt& n, const BigInt& d,
                    const BigInt& p, const BigInt& q, const BigInt& d1,
                    const BigInt& d2, const BigInt& c)
   {
   Library_State::Engine_Iterator i(global_state());

   while(const Engine* engine = i.next())
      {
      IF_Operation* op = engine->if_op(e, n, d, p, q, d1, d2, c);
      if(op)
         return op;
      }

   throw Lookup_Error("Engine_Core::if_op: Unable to find a working engine");
   }
#endif

#if defined(BOTAN_HAS_DSA)
/*************************************************
* Acquire a DSA op                               *
*************************************************/
DSA_Operation* dsa_op(const DL_Group& group, const BigInt& y, const BigInt& x)
   {
   Library_State::Engine_Iterator i(global_state());

   while(const Engine* engine = i.next())
      {
      DSA_Operation* op = engine->dsa_op(group, y, x);
      if(op)
         return op;
      }

   throw Lookup_Error("Engine_Core::dsa_op: Unable to find a working engine");
   }
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
/*************************************************
* Acquire a NR op                                *
*************************************************/
NR_Operation* nr_op(const DL_Group& group, const BigInt& y, const BigInt& x)
   {
   Library_State::Engine_Iterator i(global_state());

   while(const Engine* engine = i.next())
      {
      NR_Operation* op = engine->nr_op(group, y, x);
      if(op)
         return op;
      }

   throw Lookup_Error("Engine_Core::nr_op: Unable to find a working engine");
   }
#endif

#if defined(BOTAN_HAS_ELGAMAL)
/*************************************************
* Acquire an ElGamal op                          *
*************************************************/
ELG_Operation* elg_op(const DL_Group& group, const BigInt& y, const BigInt& x)
   {
   Library_State::Engine_Iterator i(global_state());

   while(const Engine* engine = i.next())
      {
      ELG_Operation* op = engine->elg_op(group, y, x);
      if(op)
         return op;
      }

   throw Lookup_Error("Engine_Core::elg_op: Unable to find a working engine");
   }
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
/*************************************************
* Acquire a DH op                                *
*************************************************/
DH_Operation* dh_op(const DL_Group& group, const BigInt& x)
   {
   Library_State::Engine_Iterator i(global_state());

   while(const Engine* engine = i.next())
      {
      DH_Operation* op = engine->dh_op(group, x);
      if(op)
         return op;
      }

   throw Lookup_Error("Engine_Core::dh_op: Unable to find a working engine");
   }
#endif

#if defined(BOTAN_HAS_ECDSA)
/*************************************************
* Acquire an ECDSA op                            *
*************************************************/
ECDSA_Operation* ecdsa_op(const EC_Domain_Params& dom_pars,
                          const BigInt& priv_key,
                          const PointGFp& pub_key)
   {
   Library_State::Engine_Iterator i(global_state());

   while(const Engine* engine = i.next())
      {
      ECDSA_Operation* op = engine->ecdsa_op(dom_pars, priv_key, pub_key);
      if(op)
         return op;
      }

   throw Lookup_Error("Engine_Core::ecdsa_op: Unable to find a working engine");
   }
#endif

#if defined(BOTAN_HAS_ECKAEG)
/*************************************************
* Acquire a ECKAEG op                            *
*************************************************/
ECKAEG_Operation* eckaeg_op(const EC_Domain_Params& dom_pars,
                            const BigInt& priv_key,
                            const PointGFp& pub_key)
   {
   Library_State::Engine_Iterator i(global_state());

   while(const Engine* engine = i.next())
      {
      ECKAEG_Operation* op = engine->eckaeg_op(dom_pars, priv_key, pub_key);
      if(op)
         return op;
      }

   throw Lookup_Error("Engine_Core::eckaeg_op: Unable to find a working engine");
   }
#endif

/*************************************************
* Acquire a modular exponentiator                *
*************************************************/
Modular_Exponentiator* mod_exp(const BigInt& n, Power_Mod::Usage_Hints hints)
   {
   Library_State::Engine_Iterator i(global_state());

   while(const Engine* engine = i.next())
      {
      Modular_Exponentiator* op = engine->mod_exp(n, hints);

      if(op)
         return op;
      }

   throw Lookup_Error("Engine_Core::mod_exp: Unable to find a working engine");
   }

}

}
