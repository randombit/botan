/**
* Engine Base Class
* (C) 1999-2007 Jack Lloyd
*/

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

      Algorithm_Cache_Impl(Mutex* m) : mutex(m) {}

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
const HashFunction*
Engine::prototype_hash_function(const SCAN_Name& request,
                                Algorithm_Factory& af) const
   {
   // This needs to respect provider settings
   HashFunction* algo = cache_of_hf->get(request.as_string());
   if(algo)
      return algo;

   // cache miss: do full search
   algo = find_hash(request, af);
   if(algo)
      cache_of_hf->add(algo, request.as_string());

   return algo;
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
   cache_of_bc = new Algorithm_Cache_Impl<BlockCipher>(
      global_state().get_mutex());

   cache_of_sc = new Algorithm_Cache_Impl<StreamCipher>(
      global_state().get_mutex());

   cache_of_hf = new Algorithm_Cache_Impl<HashFunction>(
      global_state().get_mutex());

   cache_of_mac = new Algorithm_Cache_Impl<MessageAuthenticationCode>(
      global_state().get_mutex());
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

}
