/*
* (C) 2009 Jack Lloyd
* (C) 2016 René Korthaus, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TESTS_FIXED_RNG_H__
#define BOTAN_TESTS_FIXED_RNG_H__

#include "tests.h"
#include <deque>
#include <string>
#include <botan/rng.h>
#include <botan/hex.h>
#include <botan/exceptn.h>

#if defined(BOTAN_HAS_SYSTEM_RNG)
  #include <botan/system_rng.h>
#else
  #include <botan/auto_rng.h>
#endif


namespace Botan_Tests {

/**
 * RNG that outputs only a given set of fixed bytes, throws otherwise.
 * Useful for test vectors with fixed nonces, where the algorithm consumes only the fixed nonce.
 */
class Fixed_Output_RNG : public Botan::RandomNumberGenerator
   {
   public:
      bool is_seeded() const override { return !m_buf.empty(); }

      virtual uint8_t random()
         {
         if(!is_seeded())
            throw Test_Error("Fixed output RNG ran out of bytes, test bug?");

         uint8_t out = m_buf.front();
         m_buf.pop_front();
         return out;
         }

      size_t reseed_with_sources(Botan::Entropy_Sources&,
                                 size_t,
                                 std::chrono::milliseconds) override { return 0; }

      void randomize(uint8_t out[], size_t len) override
         {
         for(size_t j = 0; j != len; j++)
            out[j] = random();
         }

      void add_entropy(const uint8_t b[], size_t s) override
         {
         m_buf.insert(m_buf.end(), b, b + s);
         }

      std::string name() const override { return "Fixed_Output_RNG"; }

      void clear() throw() override {}

      explicit Fixed_Output_RNG(const std::vector<uint8_t>& in)
         {
         m_buf.insert(m_buf.end(), in.begin(), in.end());
         }

      explicit Fixed_Output_RNG(const std::string& in_str)
         {
         std::vector<uint8_t> in = Botan::hex_decode(in_str);
         m_buf.insert(m_buf.end(), in.begin(), in.end());
         }

      Fixed_Output_RNG() {}
   protected:
      size_t remaining() const { return m_buf.size(); }

      std::deque<uint8_t> m_buf;
   };

/**
 * RNG that outputs a given set of fixed bytes for a specific request count, outputs random otherwise.
 * Useful for test vectors with fixed nonces, where the algorithm consumes more random than just the fixed nonce.
 */
class Fixed_Output_Position_RNG : public Fixed_Output_RNG
   {
   public:
      bool is_seeded() const override { return !m_buf.empty() || m_rng->is_seeded(); }

      uint8_t random() override
         {
         if(m_buf.empty())
            {
            throw Test_Error("Fixed output RNG ran out of bytes, test bug?");
            }

         uint8_t out = m_buf.front();
         m_buf.pop_front();
         return out;
         }

      void randomize(uint8_t out[], size_t len) override
         {
         ++m_requests;

         if(m_requests == m_pos)
            { // return fixed output
            for(size_t j = 0; j != len; j++)
               {
               out[j] = random();
               }
            }
         else
            { // return random
               m_rng->randomize(out,len);
            }
         }

      void add_entropy(const uint8_t*, size_t) override
         {
         throw Botan::Exception("add_entropy() not supported by this RNG, test bug?");
         }

      std::string name() const override { return "Fixed_Output_Position_RNG"; }

      explicit Fixed_Output_Position_RNG(const std::vector<uint8_t>& in, uint32_t pos) :
            Fixed_Output_RNG(in),
            m_pos(pos),
            m_rng{}
         {
#if defined(BOTAN_HAS_SYSTEM_RNG)
   m_rng.reset(new Botan::System_RNG);
#else
   m_rng.reset(new Botan::AutoSeeded_RNG);
#endif
         }

      explicit Fixed_Output_Position_RNG(const std::string& in_str, uint32_t pos) :
            Fixed_Output_RNG(in_str),
            m_pos(pos),
            m_rng{}
         {
#if defined(BOTAN_HAS_SYSTEM_RNG)
   m_rng.reset(new Botan::System_RNG);
#else
   m_rng.reset(new Botan::AutoSeeded_RNG);
#endif
         }

   private:
      uint32_t m_pos = 0;
      uint32_t m_requests = 0;
      std::unique_ptr<RandomNumberGenerator> m_rng;
   };

}

#endif
