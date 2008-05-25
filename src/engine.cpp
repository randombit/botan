/*************************************************
* Engine Source File                             *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/engine.h>
#include <botan/libstate.h>
#include <botan/eng_def.h>
#include <iostream>


using namespace Botan::math::ec;


namespace Botan {

namespace Engine_Core {

/*************************************************
* Acquire an IF op                               *
*************************************************/
std::tr1::shared_ptr<IF_Operation> if_op(const BigInt& e, const BigInt& n, const BigInt& d,
                    const BigInt& p, const BigInt& q, const BigInt& d1,
                    const BigInt& d2, const BigInt& c)
   {
   Library_State::Engine_Iterator i(global_state());

   while(const std::tr1::shared_ptr<Engine> engine = i.next())
      {
	  std::tr1::shared_ptr<IF_Operation> op = engine->if_op(e, n, d, p, q, d1, d2, c);
      if(op.get()) // any pointer set?
         return op;
      }

   throw Lookup_Error("Engine_Core::if_op: Unable to find a working engine");
   }

/*************************************************
* Acquire a DSA op                               *
*************************************************/
/*
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
*/
/*************************************************
* Acquire a NR op                                *
*************************************************/
/*
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
*/
/*************************************************
* Acquire an ElGamal op                          *
*************************************************/
/*
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
*/
/*************************************************
* Acquire a DH op                                *
*************************************************/
std::tr1::shared_ptr<DH_Operation> dh_op(const DL_Group& group, const BigInt& x)
   {
   Library_State::Engine_Iterator i(global_state());

   while(const std::tr1::shared_ptr<Engine> engine = i.next())
      {
	   std::tr1::shared_ptr<DH_Operation> op = engine->dh_op(group, x);
      if(op.get())
         return op;
      }

   throw Lookup_Error("Engine_Core::ecdsa_op: Unable to find a working engine");
   }

/*************************************************
* Acquire an ECDSA op                            *
*************************************************/
   std::tr1::shared_ptr<ECDSA_Operation> ecdsa_op(EC_Domain_Params const& dom_pars, BigInt const& priv_key, PointGFp const& pub_key)
   {
       Library_State::Engine_Iterator i(global_state());

       while(const std::tr1::shared_ptr<Engine> engine = i.next())
       {
           std::tr1::shared_ptr<ECDSA_Operation> op = engine->ecdsa_op(dom_pars, priv_key, pub_key);
           if(op.get())
               return op;
       }

       throw Lookup_Error("Engine_Core::ecdsa_op: Unable to find a working engine");

   }
/*************************************************
* Acquire a ECKAEG op                            *
*************************************************/
   std::tr1::shared_ptr<ECKAEG_Operation> eckaeg_op(EC_Domain_Params const& dom_pars, BigInt const& priv_key, PointGFp const& pub_key)
      {
       Library_State::Engine_Iterator i(global_state());

      while(const std::tr1::shared_ptr<Engine> engine = i.next())
         {
          std::tr1::shared_ptr<ECKAEG_Operation> op = engine->eckaeg_op(dom_pars, priv_key, pub_key);
         if(op.get())
            return op;
         }
      throw Lookup_Error("Engine_Core::eckaeg_op: Unable to find a working engine");
      }

/*************************************************
* Acquire a modular exponentiator                *
*************************************************/
std::auto_ptr<Modular_Exponentiator> mod_exp(const BigInt& n, Power_Mod::Usage_Hints hints)
   {
   Library_State::Engine_Iterator i(global_state());

   while(const std::tr1::shared_ptr<Engine> engine = i.next())
      {
	  std::auto_ptr<Modular_Exponentiator> op = engine->mod_exp(n, hints);

      if(op.get())
         return op;
      }

   throw Lookup_Error("Engine_Core::mod_exp: Unable to find a working engine");
   }

}

/*************************************************
* Acquire a block cipher                         *
*************************************************/
std::tr1::shared_ptr<BlockCipher const> retrieve_block_cipher(const std::string& name)
   {
   Library_State::Engine_Iterator i(global_state());

   while(const std::tr1::shared_ptr<Engine> engine = i.next())
      {
      std::tr1::shared_ptr<BlockCipher const> algo = engine->block_cipher(name);
      if(algo.get())
         return algo;
      }

   return std::tr1::shared_ptr<BlockCipher>();
   }

/*************************************************
* Acquire a stream cipher                        *
*************************************************/
std::tr1::shared_ptr<StreamCipher const> retrieve_stream_cipher(const std::string& name)
   {
   Library_State::Engine_Iterator i(global_state());

   while(const std::tr1::shared_ptr<Engine> engine = i.next())
      {
      std::tr1::shared_ptr<StreamCipher const> algo = engine->stream_cipher(name);
      if(algo.get())
         return algo;
      }

   return std::tr1::shared_ptr<StreamCipher>();
   }

/*************************************************
* Acquire a hash function                        *
*************************************************/
std::tr1::shared_ptr<HashFunction const> retrieve_hash(const std::string& name)
   {
   Library_State::Engine_Iterator i(global_state());

   while(const std::tr1::shared_ptr<Engine> engine = i.next())
      {
      std::tr1::shared_ptr<HashFunction const> algo = engine->hash(name);
      if(algo.get())
         return algo;
      }

   return std::tr1::shared_ptr<HashFunction>();
   }

/*************************************************
* Acquire an authentication code                 *
*************************************************/
std::tr1::shared_ptr<MessageAuthenticationCode const> retrieve_mac(const std::string& name)
   {
   Library_State::Engine_Iterator i(global_state());

   while(const std::tr1::shared_ptr<Engine> engine = i.next())
      {
      std::tr1::shared_ptr<MessageAuthenticationCode const> algo = engine->mac(name);
      if(algo.get())
         return algo;
      }

   return std::tr1::shared_ptr<MessageAuthenticationCode>();
   }

/*************************************************
* Acquire a string-to-key algorithm              *
*************************************************/
std::tr1::shared_ptr<S2K const> retrieve_s2k(const std::string& name)
   {
   Library_State::Engine_Iterator i(global_state());

   while(const std::tr1::shared_ptr<Engine> engine = i.next())
      {
      std::tr1::shared_ptr<S2K const> algo = engine->s2k(name);
      if(algo.get())
         return algo;
      }

   return std::tr1::shared_ptr<S2K>();
   }
/*************************************************
* Retrieve a block cipher padding method         *
*************************************************/
std::tr1::shared_ptr<BlockCipherModePaddingMethod const> retrieve_bc_pad(const std::string& name)
   {
   Library_State::Engine_Iterator i(global_state());

   while(const std::tr1::shared_ptr<Engine> engine = i.next())
      {
      std::tr1::shared_ptr<BlockCipherModePaddingMethod const> algo = engine->bc_pad(name);
      if(algo.get())
         return algo;
      }

   return std::tr1::shared_ptr<BlockCipherModePaddingMethod>();
   }

/*************************************************
* Add a new block cipher                         *
*************************************************/
void add_algorithm_bc(SharedPtrConverter<BlockCipher> const& algo)
   {
   Library_State::Engine_Iterator i(global_state());

   while(std::tr1::shared_ptr<Engine> engine_base = i.next())
      {
      std::tr1::shared_ptr<Default_Engine> engine = std::tr1::dynamic_pointer_cast<Default_Engine>(engine_base);
      if(engine)
         {
         engine->add_algorithm_bc(algo.get_shared());
         return;
         }
      }

   throw Invalid_State("add_algorithm: Couldn't find the Default_Engine");
   }

/*************************************************
* Add a new stream cipher                        *
*************************************************/
void add_algorithm_sc(SharedPtrConverter<StreamCipher> const& algo)
   {
   Library_State::Engine_Iterator i(global_state());

   while(std::tr1::shared_ptr<Engine> engine_base = i.next())
      {
      std::tr1::shared_ptr<Default_Engine> engine = std::tr1::dynamic_pointer_cast<Default_Engine>(engine_base);
      if(engine)
         {
         engine->add_algorithm_sc(algo.get_shared());
         return;
         }
      }

   throw Invalid_State("add_algorithm: Couldn't find the Default_Engine");
   }

/*************************************************
* Add a new hash function                        *
*************************************************/
void add_algorithm_hf(SharedPtrConverter<HashFunction> const& algo)
   {
   Library_State::Engine_Iterator i(global_state());

   while(std::tr1::shared_ptr<Engine> engine_base = i.next())
      {
      std::tr1::shared_ptr<Default_Engine> engine = std::tr1::dynamic_pointer_cast<Default_Engine>(engine_base);
      if(engine)
         {
         engine->add_algorithm_hf(algo.get_shared());
         return;
         }
      }

   throw Invalid_State("add_algorithm: Couldn't find the Default_Engine");
   }

/*************************************************
* Add a new authentication code                  *
*************************************************/
void add_algorithm_mac(SharedPtrConverter<MessageAuthenticationCode> const& algo)
   {
   Library_State::Engine_Iterator i(global_state());

   while(std::tr1::shared_ptr<Engine> engine_base = i.next())
      {
      std::tr1::shared_ptr<Default_Engine> engine = std::tr1::dynamic_pointer_cast<Default_Engine>(engine_base);
      if(engine)
         {
         engine->add_algorithm_mac(algo.get_shared());
         return;
         }
      }

   throw Invalid_State("add_algorithm: Couldn't find the Default_Engine");
   }

/*************************************************
* Add a padding method to the lookup table       *
*************************************************/
void add_algorithm_bcmpm(SharedPtrConverter<BlockCipherModePaddingMethod> const& algo)
   {
   Library_State::Engine_Iterator i(global_state());

   while(std::tr1::shared_ptr<Engine> engine_base = i.next())
      {
      std::tr1::shared_ptr<Default_Engine> engine = std::tr1::dynamic_pointer_cast<Default_Engine>(engine_base);
      if(engine)
         {
         engine->add_algorithm_bcmpm(algo.get_shared());
         return;
         }
      }

   throw Invalid_State("add_algorithm: Couldn't find the Default_Engine");
   }

/*************************************************
* Get a cipher object                            *
*************************************************/
Engine::Keyed_Filter_Ptr get_cipher(const std::string& algo_spec, Cipher_Dir direction)
   {
   Library_State::Engine_Iterator i(global_state());

   while(std::tr1::shared_ptr<Engine> engine = i.next())
      {
      Engine::Keyed_Filter_Ptr algo = engine->get_cipher(algo_spec, direction);
      if(algo.get())
         return algo;
      }

   throw Algorithm_Not_Found(algo_spec);
   }

/*************************************************
* Get a cipher object                            *
*************************************************/
Engine::Keyed_Filter_Ptr get_cipher(const std::string& algo_spec, const SymmetricKey& key,
                         const InitializationVector& iv, Cipher_Dir direction)
   {
   Engine::Keyed_Filter_Ptr cipher = get_cipher(algo_spec, direction);
   cipher->set_key(key);
   cipher->set_iv(iv);
   return cipher;
   }

/*************************************************
* Get a cipher object                            *
*************************************************/
Engine::Keyed_Filter_Ptr get_cipher(const std::string& algo_spec, const SymmetricKey& key,
                         Cipher_Dir direction)
   {
   return get_cipher(algo_spec, key, InitializationVector(), direction);
   }

}
