/*************************************************
* Library Internal/Global State Header File      *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_LIB_STATE_H__
#define BOTAN_LIB_STATE_H__

#include <botan/base.h>
#include <botan/enums.h>
#include <botan/init.h>
#include <botan/ui.h>
#include <string>
#include <vector>
#include <map>

namespace Botan {

/*************************************************
* Global State Container Base                    *
*************************************************/
class Library_State
   {
   public:
      Library_State();
      ~Library_State();

      void initialize(const InitializerOptions&, Modules&);

      void load(Modules&);

      void add_engine(class Engine*);

      class Engine_Iterator
         {
         public:
            class Engine* next();
            Engine_Iterator(const Library_State& l) : lib(l) { n = 0; }
         private:
            const Library_State& lib;
            u32bit n;
         };
      friend class Engine_Iterator;

      class UI
         {
         public:
            virtual void pulse(Pulse_Type) {}
            virtual ~UI() {}
         };

      Allocator* get_allocator(const std::string& = "") const;
      void add_allocator(Allocator*);
      void set_default_allocator(const std::string&) const;

      bool rng_is_seeded() const { return rng->is_seeded(); }
      void randomize(byte[], u32bit);

      void set_prng(RandomNumberGenerator*);
      void add_entropy_source(EntropySource*, bool = true);
      void add_entropy(const byte[], u32bit);
      void add_entropy(EntropySource&, bool);
      u32bit seed_prng(bool, u32bit);

      void set_timer(class Timer*);
      u64bit system_clock() const;

      class Config& config() const;

      class Mutex* get_mutex() const;
      class Mutex* get_named_mutex(const std::string&);

      void set_x509_state(class X509_GlobalState*);
      class X509_GlobalState& x509_state();

      void pulse(Pulse_Type) const;
      void set_ui(UI*);

      void set_transcoder(class Charset_Transcoder*);
      std::string transcode(const std::string,
                            Character_Set, Character_Set) const;
   private:
      Library_State(const Library_State&) {}
      Library_State& operator=(const Library_State&) { return (*this); }

      class Engine* get_engine_n(u32bit) const;

      class Mutex_Factory* mutex_factory;
      class Timer* timer;
      mutable class Config* config_obj;
      class X509_GlobalState* x509_state_obj;

      std::map<std::string, class Mutex*> locks;
      std::map<std::string, Allocator*> alloc_factory;
      mutable Allocator* cached_default_allocator;

      UI* ui;
      class Charset_Transcoder* transcoder;
      RandomNumberGenerator* rng;
      std::vector<Allocator*> allocators;
      std::vector<EntropySource*> entropy_sources;
      std::vector<class Engine*> engines;
   };

/*************************************************
* Global State                                   *
*************************************************/
Library_State& global_state();
void set_global_state(Library_State*);
Library_State* swap_global_state(Library_State*);

}

#endif
