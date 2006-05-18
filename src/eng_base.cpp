/*************************************************
* Basic No-Op Engine Source File                 *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/engine.h>
#include <botan/libstate.h>
#include <botan/stl_util.h>
#include <botan/lookup.h>

namespace Botan {

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
* Get an algorithm out of the table              *
*************************************************/
Algorithm* Engine::get_algo(const std::string& type,
                            const std::string& name) const
   {
   Mutex_Holder lock(mappings[type].first);
   return search_map(mappings[type].second, name);
   }

/*************************************************
* Add an algorithm to the appropriate table      *
*************************************************/
void Engine::add_algo(const std::string& type, Algorithm* algo) const
   {
   if(!algo)
      return;

   Mutex_Holder lock(mappings[type].first);

   std::map<std::string, Algorithm*>& map = mappings[type].second;

   const std::string algo_name = algo->name();

   if(map.find(algo_name) != map.end())
      delete map[algo_name];
   map[algo_name] = algo;
   }

/*************************************************
* Acquire a BlockCipher                          *
*************************************************/
const BlockCipher* Engine::block_cipher(const std::string& name) const
   {
   const std::string real_name = deref_alias(name);

   Algorithm* got = get_algo("block_cipher", real_name);

   if(got)
      return dynamic_cast<BlockCipher*>(got);

   BlockCipher* to_return = find_block_cipher(real_name);
   add_algorithm(to_return);
   return to_return;
   }

/*************************************************
* Acquire a StreamCipher                         *
*************************************************/
const StreamCipher* Engine::stream_cipher(const std::string& name) const
   {
   const std::string real_name = deref_alias(name);

   Algorithm* got = get_algo("stream_cipher", real_name);

   if(got)
      return dynamic_cast<StreamCipher*>(got);

   StreamCipher* to_return = find_stream_cipher(real_name);
   add_algorithm(to_return);
   return to_return;
   }

/*************************************************
* Acquire a HashFunction                         *
*************************************************/
const HashFunction* Engine::hash(const std::string& name) const
   {
   const std::string real_name = deref_alias(name);

   Algorithm* got = get_algo("hash_func", real_name);

   if(got)
      return dynamic_cast<HashFunction*>(got);

   HashFunction* to_return = find_hash(real_name);
   add_algorithm(to_return);
   return to_return;
   }

/*************************************************
* Acquire a MessageAuthenticationCode            *
*************************************************/
const MessageAuthenticationCode* Engine::mac(const std::string& name) const
   {
   const std::string real_name = deref_alias(name);

   Algorithm* got = get_algo("mac_func", real_name);

   if(got)
      return dynamic_cast<MessageAuthenticationCode*>(got);

   MessageAuthenticationCode* to_return = find_mac(real_name);
   add_algorithm(to_return);
   return to_return;
   }

/*************************************************
* Acquire a S2K object                           *
*************************************************/
const S2K* Engine::s2k(const std::string& name) const
   {
   const std::string real_name = deref_alias(name);

   Algorithm* got = get_algo("s2k_func", real_name);

   if(got)
      return dynamic_cast<S2K*>(got);

   S2K* to_return = find_s2k(real_name);
   add_algorithm(to_return);
   return to_return;
   }

/*************************************************
* Acquire a cipher padding object                *
*************************************************/
const BlockCipherModePaddingMethod*
Engine::bc_pad(const std::string& name) const
   {
   const std::string real_name = deref_alias(name);

   Algorithm* got = get_algo("bc_pad", real_name);

   if(got)
      return dynamic_cast<BlockCipherModePaddingMethod*>(got);

   BlockCipherModePaddingMethod* to_return =
      find_bc_pad(real_name);

   add_algorithm(to_return);
   return to_return;
   }

/*************************************************
* Add a block cipher to the lookup table         *
*************************************************/
void Engine::add_algorithm(BlockCipher* algo) const
   {
   add_algo("block_cipher", algo);
   }

/*************************************************
* Add a stream cipher to the lookup table        *
*************************************************/
void Engine::add_algorithm(StreamCipher* algo) const
   {
   add_algo("stream_cipher", algo);
   }

/*************************************************
* Add a hash function to the lookup table        *
*************************************************/
void Engine::add_algorithm(HashFunction* algo) const
   {
   add_algo("hash_func", algo);
   }

/*************************************************
* Add a MAC to the lookup table                  *
*************************************************/
void Engine::add_algorithm(MessageAuthenticationCode* algo) const
   {
   add_algo("mac_func", algo);
   }

/*************************************************
* Add a S2K to the lookup table                  *
*************************************************/
void Engine::add_algorithm(S2K* algo) const
   {
   add_algo("s2k_func", algo);
   }

/*************************************************
* Add a cipher pad method to the lookup table    *
*************************************************/
void Engine::add_algorithm(BlockCipherModePaddingMethod* algo) const
   {
   add_algo("bc_pad", algo);
   }

/*************************************************
* Create an Engine                               *
*************************************************/
Engine::Engine()
   {
   const std::string TYPES[] = {
      "block_cipher", "stream_cipher", "hash_func", "mac_func",
      "s2k_func", "bc_pad", ""
   };

   for(u32bit j = 0; TYPES[j] != ""; ++j)
      {
      mappings[TYPES[j]] =
         std::make_pair(global_state().get_mutex(),
                        std::map<std::string, Algorithm*>());
      }
   }

/*************************************************
* Destroy an Engine                              *
*************************************************/
Engine::~Engine()
   {
   std::map<std::string, mutex_map_pair>::iterator i = mappings.begin();
   while(i != mappings.end())
      {
      delete i->second.first;

      std::map<std::string, Algorithm*>::iterator j =
         i->second.second.begin();
      while(j != i->second.second.end())
         {
         delete j->second;
         ++j;
         }

      ++i;
      }
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
