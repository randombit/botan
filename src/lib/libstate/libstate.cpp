/*
* Library Internal/Global State
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/libstate.h>
#include <botan/charset.h>
#include <botan/engine.h>
#include <botan/cpuid.h>
#include <botan/oids.h>
#include <botan/internal/core_engine.h>
#include <botan/internal/stl_util.h>
#include <algorithm>

#if defined(BOTAN_HAS_SELFTESTS)
  #include <botan/selftest.h>
#endif

#if defined(BOTAN_HAS_ENGINE_ASSEMBLER)
  #include <botan/internal/asm_engine.h>
#endif

#if defined(BOTAN_HAS_ENGINE_AES_ISA)
  #include <botan/internal/aes_isa_engine.h>
#endif

#if defined(BOTAN_HAS_ENGINE_SIMD)
  #include <botan/internal/simd_engine.h>
#endif

#if defined(BOTAN_HAS_ENGINE_GNU_MP)
  #include <botan/internal/gnump_engine.h>
#endif

#if defined(BOTAN_HAS_ENGINE_OPENSSL)
  #include <botan/internal/openssl_engine.h>
#endif

namespace Botan {

/*
* Return a reference to the Algorithm_Factory
*/
Algorithm_Factory& Library_State::algorithm_factory() const
   {
   if(!m_algorithm_factory)
      throw Invalid_State("Uninitialized in Library_State::algorithm_factory");
   return *m_algorithm_factory;
   }

/*
* Return a reference to the global PRNG
*/
RandomNumberGenerator& Library_State::global_rng()
   {
   return *m_global_prng;
   }

Library_State::~Library_State()
   {
   }

void Library_State::initialize()
   {
   if(m_algorithm_factory.get())
      throw Invalid_State("Library_State has already been initialized");

   CPUID::initialize();

   SCAN_Name::set_default_aliases();
   OIDS::set_defaults();

   m_algorithm_factory.reset(new Algorithm_Factory());

#if defined(BOTAN_HAS_ENGINE_GNU_MP)
   algorithm_factory().add_engine(new GMP_Engine);
#endif

#if defined(BOTAN_HAS_ENGINE_OPENSSL)
   algorithm_factory().add_engine(new OpenSSL_Engine);
#endif

#if defined(BOTAN_HAS_ENGINE_AES_ISA)
   algorithm_factory().add_engine(new AES_ISA_Engine);
#endif

#if defined(BOTAN_HAS_ENGINE_SIMD)
   algorithm_factory().add_engine(new SIMD_Engine);
#endif

#if defined(BOTAN_HAS_ENGINE_ASSEMBLER)
   algorithm_factory().add_engine(new Assembler_Engine);
#endif

   algorithm_factory().add_engine(new Core_Engine);

   m_sources = entropy_sources();

   m_global_prng.reset(new Serialized_RNG());

#if defined(BOTAN_HAS_SELFTESTS)
   confirm_startup_self_tests(algorithm_factory());
#endif
   }

}
