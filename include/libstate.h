/*************************************************
* Library Internal/Global State Header File      *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_LIB_STATE_H__
#define BOTAN_LIB_STATE_H__

#include <botan/base.h>
#include <botan/enums.h>
#include <botan/ui.h>
#include <botan/freestore.h>
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
      class Engine_Iterator
         {
         public:
            std::tr1::shared_ptr<class Engine> next();
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

      std::tr1::shared_ptr<Allocator> get_allocator(const std::string& = "") const;
      void add_allocator(SharedPtrConverter<Allocator>);
      void set_default_allocator(const std::string&) const;

      bool rng_is_seeded() const { return rng->is_seeded(); }
      void randomize(byte[], u32bit);

      void set_prng(RandomNumberGenerator*);
      void add_entropy_source(SharedPtrConverter<EntropySource>, bool = true);
      void add_entropy(const byte[], u32bit);
      void add_entropy(EntropySource&, bool);
      u32bit seed_prng(bool, u32bit);

      void load(class Modules&);

      void set_timer(SharedPtrConverter<class Timer>);
      u64bit system_clock() const;

      class Config& config() const;

      void add_engine(SharedPtrConverter<class Engine>);

      std::auto_ptr<class Mutex> get_mutex() const;
      std::tr1::shared_ptr<class Mutex> get_named_mutex(const std::string&);

      void set_x509_state(SharedPtrConverter<class X509_GlobalState>);
      std::tr1::shared_ptr<class X509_GlobalState> x509_state();

      void pulse(Pulse_Type) const;
      void set_ui(SharedPtrConverter<UI>);

      void set_transcoder(SharedPtrConverter<class Charset_Transcoder>);
      std::string transcode(const std::string,
                            Character_Set, Character_Set) const;

      Library_State(SharedPtrConverter<class Mutex_Factory>);
      ~Library_State();
   private:
      Library_State(const Library_State&) {}
      Library_State& operator=(const Library_State&) { return (*this); }

      std::tr1::shared_ptr<class Engine> get_engine_n(u32bit) const;

      std::tr1::shared_ptr<class Mutex_Factory> mutex_factory;
      std::tr1::shared_ptr<class Timer> timer;
      std::tr1::shared_ptr<class Config> config_obj;
      std::tr1::shared_ptr<class X509_GlobalState> x509_state_obj;

      std::map<std::string, std::tr1::shared_ptr<class Mutex> > locks;
      std::map<std::string, std::tr1::shared_ptr<Allocator> > alloc_factory;
      mutable std::tr1::shared_ptr<Allocator> cached_default_allocator;

      std::tr1::shared_ptr<UI> ui;
      std::tr1::shared_ptr<class Charset_Transcoder> transcoder;
      RandomNumberGenerator* rng;
      //std::tr1::shared_ptr<RandomNumberGenerator> rng;

      std::vector<std::tr1::shared_ptr<Allocator> > allocators;
      std::vector<std::tr1::shared_ptr<EntropySource> > entropy_sources;
      std::vector<std::tr1::shared_ptr<class Engine> > engines;
   };

/*************************************************
* Global State                                   *
*************************************************/
Library_State& global_state();
//void set_global_state(std::tr1::shared_ptr<Library_State>);
//std::tr1::shared_ptr<Library_State> swap_global_state(std::tr1::shared_ptr<Library_State>);
void set_global_state(Library_State*);
Library_State* swap_global_state(Library_State*);


}

#endif
