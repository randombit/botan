/*************************************************
* Engine Source File                             *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/engine.h>
#include <botan/libstate.h>
#include <botan/eng_def.h>

namespace Botan {

namespace Engine_Core {

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

/*************************************************
* Acquire a block cipher                         *
*************************************************/
const BlockCipher* retrieve_block_cipher(const std::string& name)
   {
   Library_State::Engine_Iterator i(global_state());

   while(const Engine* engine = i.next())
      {
      const BlockCipher* algo = engine->block_cipher(name);
      if(algo)
         return algo;
      }

   return 0;
   }

/*************************************************
* Acquire a stream cipher                        *
*************************************************/
const StreamCipher* retrieve_stream_cipher(const std::string& name)
   {
   Library_State::Engine_Iterator i(global_state());

   while(const Engine* engine = i.next())
      {
      const StreamCipher* algo = engine->stream_cipher(name);
      if(algo)
         return algo;
      }

   return 0;
   }

/*************************************************
* Acquire a hash function                        *
*************************************************/
const HashFunction* retrieve_hash(const std::string& name)
   {
   Library_State::Engine_Iterator i(global_state());

   while(const Engine* engine = i.next())
      {
      const HashFunction* algo = engine->hash(name);
      if(algo)
         return algo;
      }

   return 0;
   }

/*************************************************
* Acquire an authentication code                 *
*************************************************/
const MessageAuthenticationCode* retrieve_mac(const std::string& name)
   {
   Library_State::Engine_Iterator i(global_state());

   while(const Engine* engine = i.next())
      {
      const MessageAuthenticationCode* algo = engine->mac(name);
      if(algo)
         return algo;
      }

   return 0;
   }

/*************************************************
* Acquire a string-to-key algorithm              *
*************************************************/
const S2K* retrieve_s2k(const std::string& name)
   {
   Library_State::Engine_Iterator i(global_state());

   while(const Engine* engine = i.next())
      {
      const S2K* algo = engine->s2k(name);
      if(algo)
         return algo;
      }

   return 0;
   }

/*************************************************
* Retrieve a block cipher padding method         *
*************************************************/
const BlockCipherModePaddingMethod* retrieve_bc_pad(const std::string& name)
   {
   Library_State::Engine_Iterator i(global_state());

   while(const Engine* engine = i.next())
      {
      const BlockCipherModePaddingMethod* algo = engine->bc_pad(name);
      if(algo)
         return algo;
      }

   return 0;
   }

/*************************************************
* Add a new block cipher                         *
*************************************************/
void add_algorithm(BlockCipher* algo)
   {
   Library_State::Engine_Iterator i(global_state());

   while(Engine* engine_base = i.next())
      {
      Default_Engine* engine = dynamic_cast<Default_Engine*>(engine_base);
      if(engine)
         {
         engine->add_algorithm(algo);
         return;
         }
      }

   throw Invalid_State("add_algorithm: Couldn't find the Default_Engine");
   }

/*************************************************
* Add a new stream cipher                        *
*************************************************/
void add_algorithm(StreamCipher* algo)
   {
   Library_State::Engine_Iterator i(global_state());

   while(Engine* engine_base = i.next())
      {
      Default_Engine* engine = dynamic_cast<Default_Engine*>(engine_base);
      if(engine)
         {
         engine->add_algorithm(algo);
         return;
         }
      }

   throw Invalid_State("add_algorithm: Couldn't find the Default_Engine");
   }

/*************************************************
* Add a new hash function                        *
*************************************************/
void add_algorithm(HashFunction* algo)
   {
   Library_State::Engine_Iterator i(global_state());

   while(Engine* engine_base = i.next())
      {
      Default_Engine* engine = dynamic_cast<Default_Engine*>(engine_base);
      if(engine)
         {
         engine->add_algorithm(algo);
         return;
         }
      }

   throw Invalid_State("add_algorithm: Couldn't find the Default_Engine");
   }

/*************************************************
* Add a new authentication code                  *
*************************************************/
void add_algorithm(MessageAuthenticationCode* algo)
   {
   Library_State::Engine_Iterator i(global_state());

   while(Engine* engine_base = i.next())
      {
      Default_Engine* engine = dynamic_cast<Default_Engine*>(engine_base);
      if(engine)
         {
         engine->add_algorithm(algo);
         return;
         }
      }

   throw Invalid_State("add_algorithm: Couldn't find the Default_Engine");
   }

/*************************************************
* Add a padding method to the lookup table       *
*************************************************/
void add_algorithm(BlockCipherModePaddingMethod* algo)
   {
   Library_State::Engine_Iterator i(global_state());

   while(Engine* engine_base = i.next())
      {
      Default_Engine* engine = dynamic_cast<Default_Engine*>(engine_base);
      if(engine)
         {
         engine->add_algorithm(algo);
         return;
         }
      }

   throw Invalid_State("add_algorithm: Couldn't find the Default_Engine");
   }

/*************************************************
* Get a cipher object                            *
*************************************************/
Keyed_Filter* get_cipher(const std::string& algo_spec, Cipher_Dir direction)
   {
   Library_State::Engine_Iterator i(global_state());

   while(Engine* engine = i.next())
      {
      Keyed_Filter* algo = engine->get_cipher(algo_spec, direction);
      if(algo)
         return algo;
      }

   throw Algorithm_Not_Found(algo_spec);
   }

/*************************************************
* Get a cipher object                            *
*************************************************/
Keyed_Filter* get_cipher(const std::string& algo_spec, const SymmetricKey& key,
                         const InitializationVector& iv, Cipher_Dir direction)
   {
   Keyed_Filter* cipher = get_cipher(algo_spec, direction);
   cipher->set_key(key);
   cipher->set_iv(iv);
   return cipher;
   }

/*************************************************
* Get a cipher object                            *
*************************************************/
Keyed_Filter* get_cipher(const std::string& algo_spec, const SymmetricKey& key,
                         Cipher_Dir direction)
   {
   return get_cipher(algo_spec, key, InitializationVector(), direction);
   }

}
