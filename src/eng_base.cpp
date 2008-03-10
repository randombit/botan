/*************************************************
* Basic No-Op Engine Source File                 *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/engine.h>
#include <botan/libstate.h>
#include <botan/stl_util.h>
#include <botan/lookup.h>

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
* Basic No-Op Engine Implementation              *
*************************************************/
IF_Operation* Engine::if_op(const BigInt&, const BigInt&, const BigInt&,
                            const BigInt&, const BigInt&, const BigInt&,
                            const BigInt&, const BigInt&) const
   {
   return 0;
   }

/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
DSA_Operation* Engine::dsa_op(const DL_Group&, const BigInt&,
                              const BigInt&) const
   {
   return 0;
   }

/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
NR_Operation* Engine::nr_op(const DL_Group&, const BigInt&,
                            const BigInt&) const
   {
   return 0;
   }

/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
ELG_Operation* Engine::elg_op(const DL_Group&, const BigInt&,
                              const BigInt&) const
   {
   return 0;
   }

/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
DH_Operation* Engine::dh_op(const DL_Group&, const BigInt&) const
   {
   return 0;
   }

/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
Modular_Exponentiator* Engine::mod_exp(const BigInt&,
                                       Power_Mod::Usage_Hints) const
   {
   return 0;
   }

/*************************************************
* Acquire a BlockCipher                          *
*************************************************/
const BlockCipher* Engine::block_cipher(const std::string& name) const
   {
   return lookup_algo(cache_of_bc, deref_alias(name),
                      this, &Engine::find_block_cipher);
   }

/*************************************************
* Acquire a StreamCipher                         *
*************************************************/
const StreamCipher* Engine::stream_cipher(const std::string& name) const
   {
   return lookup_algo(cache_of_sc, deref_alias(name),
                      this, &Engine::find_stream_cipher);
   }

/*************************************************
* Acquire a HashFunction                         *
*************************************************/
const HashFunction* Engine::hash(const std::string& name) const
   {
   return lookup_algo(cache_of_hf, deref_alias(name),
                      this, &Engine::find_hash);
   }

/*************************************************
* Acquire a MessageAuthenticationCode            *
*************************************************/
const MessageAuthenticationCode* Engine::mac(const std::string& name) const
   {
   return lookup_algo(cache_of_mac, deref_alias(name),
                      this, &Engine::find_mac);
   }

/*************************************************
* Acquire a S2K object                           *
*************************************************/
const S2K* Engine::s2k(const std::string& name) const
   {
   return lookup_algo(cache_of_s2k, deref_alias(name),
                      this, &Engine::find_s2k);
   }

/*************************************************
* Acquire a cipher padding object                *
*************************************************/
const BlockCipherModePaddingMethod*
Engine::bc_pad(const std::string& name) const
   {
   return lookup_algo(cache_of_bc_pad, deref_alias(name),
                      this, &Engine::find_bc_pad);
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
* Add a S2K to the lookup table                  *
*************************************************/
void Engine::add_algorithm(S2K* algo) const
   {
   cache_of_s2k->add(algo);
   }

/*************************************************
* Add a cipher pad method to the lookup table    *
*************************************************/
void Engine::add_algorithm(BlockCipherModePaddingMethod* algo) const
   {
   cache_of_bc_pad->add(algo);
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
   cache_of_s2k = new Algorithm_Cache_Impl<S2K>();
   cache_of_bc_pad =
      new Algorithm_Cache_Impl<BlockCipherModePaddingMethod>();
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
   delete cache_of_s2k;
   delete cache_of_bc_pad;
   }

/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
BlockCipher* Engine::find_block_cipher(const std::string&) const
   {
   return 0;
   }

/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
StreamCipher* Engine::find_stream_cipher(const std::string&) const
   {
   return 0;
   }

/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
HashFunction* Engine::find_hash(const std::string&) const
   {
   return 0;
   }

/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
MessageAuthenticationCode* Engine::find_mac(const std::string&) const
   {
   return 0;
   }

/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
S2K* Engine::find_s2k(const std::string&) const
   {
   return 0;
   }

/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
BlockCipherModePaddingMethod* Engine::find_bc_pad(const std::string&) const
   {
   return 0;
   }

/*************************************************
* Basic No-Op Engine Implementation              *
*************************************************/
Keyed_Filter* Engine::get_cipher(const std::string&, Cipher_Dir)
   {
   return 0;
   }

}
