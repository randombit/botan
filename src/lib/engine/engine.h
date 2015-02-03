/*
* Engine
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ENGINE_H__
#define BOTAN_ENGINE_H__

#include <botan/scan_name.h>
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/pbkdf.h>
#include <botan/pow_mod.h>
#include <botan/pk_keys.h>

namespace Botan {

class Algorithm_Factory;
class RandomNumberGenerator;

/**
* Base class for all engines. All non-pure virtual functions simply
* return NULL, indicating the algorithm in question is not
* supported. Subclasses can reimplement whichever function(s)
* they want to hook in a particular type.
*/
class BOTAN_DLL Engine
   {
   public:
      virtual ~Engine() {}

      /**
      * @return name of this engine
      */
      virtual std::string provider_name() const = 0;

      /**
      * @param algo_spec the algorithm name/specification
      * @param af an algorithm factory object
      * @return newly allocated object, or NULL
      */
      virtual BlockCipher*
         find_block_cipher(const SCAN_Name& algo_spec,
                           Algorithm_Factory& af) const;

      /**
      * @param algo_spec the algorithm name/specification
      * @param af an algorithm factory object
      * @return newly allocated object, or NULL
      */
      virtual StreamCipher*
         find_stream_cipher(const SCAN_Name& algo_spec,
                            Algorithm_Factory& af) const;

      /**
      * @param algo_spec the algorithm name/specification
      * @param af an algorithm factory object
      * @return newly allocated object, or NULL
      */
      virtual HashFunction*
         find_hash(const SCAN_Name& algo_spec,
                   Algorithm_Factory& af) const;

      /**
      * @param algo_spec the algorithm name/specification
      * @param af an algorithm factory object
      * @return newly allocated object, or NULL
      */
      virtual MessageAuthenticationCode*
         find_mac(const SCAN_Name& algo_spec,
                  Algorithm_Factory& af) const;

      /**
      * @param algo_spec the algorithm name/specification
      * @param af an algorithm factory object
      * @return newly allocated object, or NULL
      */
      virtual PBKDF* find_pbkdf(const SCAN_Name& algo_spec,
                                Algorithm_Factory& af) const;
   };

}

#endif
