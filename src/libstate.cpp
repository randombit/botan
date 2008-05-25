/*************************************************
* Library Internal/Global State Source File      *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/libstate.h>
#include <botan/config.h>
#include <botan/modules.h>
#include <botan/engine.h>
#include <botan/x509stat.h>
#include <botan/stl_util.h>
#include <botan/mutex.h>
#include <botan/timers.h>
#include <botan/charset.h>
#include <algorithm>

namespace Botan {

/*************************************************
* Botan's global state                           *
*************************************************/
namespace {

Library_State* global_lib_state = 0;
 //   std::tr1::shared_ptr<Library_State> global_lib_state = std::tr1::shared_ptr<Library_State>();
}

/*************************************************
* Access the global state object                 *
*************************************************/
Library_State& global_state()
   {
   if(!global_lib_state)
   //    if(!global_lib_state.get())
      throw Invalid_State("Library was not initialized correctly");
   return (*global_lib_state);
   //    return (*(global_lib_state.get()));
   }

/*************************************************
* Set a new global state object                  *
*************************************************/
void set_global_state(Library_State* new_state)
   {
   delete swap_global_state(new_state);
   }
/*   void set_global_state(std::tr1::shared_ptr<Library_State> new_state)
   {
       global_lib_state = new_state;
   }*/
/*************************************************
* Swap two global state objects                  *
*************************************************/
Library_State* swap_global_state(Library_State* new_state)
   {
   Library_State* old_state = global_lib_state;
   global_lib_state = new_state;
   return old_state;
   }

/*************************************************
* Increment the Engine iterator                  *
*************************************************/
std::tr1::shared_ptr<class Engine> Library_State::Engine_Iterator::next()
   {
   return lib.get_engine_n(n++);
   }

/*************************************************
* Get a new mutex object                         *
*************************************************/
std::auto_ptr<Mutex> Library_State::get_mutex() const
   {
   return mutex_factory->make();
   }

/*************************************************
* Get a persistent named mutex object            *
*************************************************/
std::tr1::shared_ptr<Mutex> Library_State::get_named_mutex(const std::string& name)
   {
   std::tr1::shared_ptr<Mutex> mux = search_map<std::string, std::tr1::shared_ptr<Mutex> >(locks, name,
	   std::tr1::shared_ptr<Mutex>());
   if(mux)
      return mux;
   return (locks[name] = std::tr1::shared_ptr<Mutex>(get_mutex().release()));
   }

/*************************************************
* Get an allocator by its name                   *
*************************************************/
std::tr1::shared_ptr<Allocator> Library_State::get_allocator(const std::string& type) const
   {
   Named_Mutex_Holder lock("allocator");

   if(type != "")
      return search_map<std::string, std::tr1::shared_ptr<Allocator> >(alloc_factory, type,
	      std::tr1::shared_ptr<Allocator>());

   if(!cached_default_allocator)
      {
      std::string chosen = config().option("base/default_allocator");

      if(chosen == "")
         chosen = "malloc";

      cached_default_allocator =
         search_map<std::string, std::tr1::shared_ptr<Allocator> >(alloc_factory, chosen,
        	 std::tr1::shared_ptr<Allocator>());
      }

   return cached_default_allocator;
   }

/*************************************************
* Create a new name to object mapping            *
*************************************************/
void Library_State::add_allocator(SharedPtrConverter<Allocator> allocator)
   {
   Named_Mutex_Holder lock("allocator");
   std::tr1::shared_ptr<Allocator> shared_alloc_ptr = allocator.get_shared();

   shared_alloc_ptr->init();

   allocators.push_back(shared_alloc_ptr);
   alloc_factory[shared_alloc_ptr->type()] = shared_alloc_ptr;
   }

/*************************************************
* Set the default allocator type                 *
*************************************************/
void Library_State::set_default_allocator(const std::string& type) const
   {
   Named_Mutex_Holder lock("allocator");

   if(type == "")
      return;

   config().set("conf", "base/default_allocator", type);
   cached_default_allocator = std::tr1::shared_ptr<Allocator>();
   }

/*************************************************
* Set the high resolution clock implementation   *
*************************************************/
void Library_State::set_timer(SharedPtrConverter<Timer> new_timer)
   {
   if(new_timer.get_shared().get())
      {
      timer = new_timer.get_shared();
      }
   }

/*************************************************
* Read a high resolution clock                   *
*************************************************/
u64bit Library_State::system_clock() const
   {
   return (timer) ? timer->clock() : 0;
   }

/*************************************************
* Set the global PRNG                            *
*************************************************/
void Library_State::set_prng(RandomNumberGenerator* new_rng)
   {
   Named_Mutex_Holder lock("rng");

   delete rng;
   rng = new_rng;
  // rng = std::tr1::shared_ptr<RandomNumberGenerator>(new_rng);

   }

/*************************************************
* Get bytes from the global PRNG                 *
*************************************************/
void Library_State::randomize(byte out[], u32bit length)
   {
   Named_Mutex_Holder lock("rng");

   rng->randomize(out, length);
   }

/*************************************************
* Add a new entropy source to use                *
*************************************************/
void Library_State::add_entropy_source(SharedPtrConverter<EntropySource> src, bool last_in_list)
   {
   Named_Mutex_Holder lock("rng");

   if(last_in_list)
      entropy_sources.push_back(src.get_shared());
   else
      entropy_sources.insert(entropy_sources.begin(), src.get_shared());
   }

/*************************************************
* Add some bytes of entropy to the global PRNG   *
*************************************************/
void Library_State::add_entropy(const byte in[], u32bit length)
   {
   Named_Mutex_Holder lock("rng");

   rng->add_entropy(in, length);
   }

/*************************************************
* Add some bytes of entropy to the global PRNG   *
*************************************************/
void Library_State::add_entropy(EntropySource& source, bool slow_poll)
   {
   Named_Mutex_Holder lock("rng");

   rng->add_entropy(source, slow_poll);
   }

/*************************************************
* Gather entropy for our PRNG object             *
*************************************************/
u32bit Library_State::seed_prng(bool slow_poll, u32bit bits_to_get)
   {
   Named_Mutex_Holder lock("rng");

   u32bit bits = 0;
   for(u32bit j = 0; j != entropy_sources.size(); ++j)
      {
      bits += rng->add_entropy(*(entropy_sources[j]), slow_poll);

      if(bits_to_get && bits >= bits_to_get)
         return bits;
      }

   return bits;
   }

/*************************************************
* Get an engine out of the list                  *
*************************************************/
std::tr1::shared_ptr<Engine> Library_State::get_engine_n(u32bit n) const
   {
   Named_Mutex_Holder lock("engine");

   if(n >= engines.size())
      return std::tr1::shared_ptr<Engine>();
   return engines[n];
   }

/*************************************************
* Add a new engine to the list                   *
*************************************************/
void Library_State::add_engine(SharedPtrConverter<Engine> engine)
   {
   Named_Mutex_Holder lock("engine");
   engines.insert(engines.begin(), engine.get_shared());
   }

/*************************************************
* Set the character set transcoder object        *
*************************************************/
void Library_State::set_transcoder(SharedPtrConverter<class Charset_Transcoder> transcoder)
   {
   this->transcoder = transcoder.get_shared();
   }

/*************************************************
* Transcode a string from one charset to another *
*************************************************/
std::string Library_State::transcode(const std::string str,
                                     Character_Set to,
                                     Character_Set from) const
   {
   if(!transcoder)
      throw Invalid_State("Library_State::transcode: No transcoder set");

   return transcoder->transcode(str, to, from);
   }

/*************************************************
* Set the X509 global state class                *
*************************************************/
void Library_State::set_x509_state(SharedPtrConverter<X509_GlobalState> new_x509_state_obj)
   {
   x509_state_obj = new_x509_state_obj.get_shared();
   }

/*************************************************
* Get the X509 global state class                *
*************************************************/
std::tr1::shared_ptr<X509_GlobalState> Library_State::x509_state()
   {
   if(!x509_state_obj)
      x509_state_obj = std::tr1::shared_ptr<X509_GlobalState>(new X509_GlobalState());

   return x509_state_obj;
   }

/*************************************************
* Set the UI object state                        *
*************************************************/
void Library_State::set_ui(SharedPtrConverter<UI> new_ui)
   {
   ui = new_ui.get_shared();
   }

/*************************************************
* Send a pulse to the UI object                  *
*************************************************/
void Library_State::pulse(Pulse_Type pulse_type) const
   {
   if(ui)
      ui->pulse(pulse_type);
   }

/*************************************************
* Set the configuration object                   *
*************************************************/
Config& Library_State::config() const
   {
   if(!config_obj)
      throw Invalid_State("Library_State::config(): No config set");

   return (*(config_obj.get()));
   }

/*************************************************
* Load modules                                   *
*************************************************/
void Library_State::load(Modules& modules)
   {
   set_timer(modules.timer());
   set_transcoder(modules.transcoder());

   std::vector<std::tr1::shared_ptr<Allocator> > mod_allocs = modules.allocators();
   for(u32bit j = 0; j != mod_allocs.size(); ++j)
      add_allocator(mod_allocs[j]);

   set_default_allocator(modules.default_allocator());

   std::vector<std::tr1::shared_ptr<Engine> > mod_engines = modules.engines();
   for(u32bit j = 0; j != mod_engines.size(); ++j)
      {
      Named_Mutex_Holder lock("engine");
      engines.push_back(mod_engines[j]);
      }

   std::vector<std::tr1::shared_ptr<EntropySource> > sources = modules.entropy_sources();
   for(u32bit j = 0; j != sources.size(); ++j)
      add_entropy_source(sources[j]);
   }

/*************************************************
* Library_State Constructor                      *
*************************************************/
Library_State::Library_State(SharedPtrConverter<Mutex_Factory> mutex_factory)
   {
   if(!mutex_factory.get_shared().get())
      throw Exception("Library_State: no mutex found");

   this->mutex_factory = mutex_factory.get_shared();
   this->timer = std::tr1::shared_ptr<Timer>(new Timer());
   this->transcoder = std::tr1::shared_ptr<Charset_Transcoder>();
   this->config_obj = std::tr1::shared_ptr<Config>(new Config());

   locks["settings"] = std::tr1::shared_ptr<Mutex>(get_mutex().release());
   locks["allocator"] = std::tr1::shared_ptr<Mutex>(get_mutex().release());
   locks["rng"] = std::tr1::shared_ptr<Mutex>(get_mutex().release());
   locks["engine"] = std::tr1::shared_ptr<Mutex>(get_mutex().release());
   rng = 0;
   //rng = std::tr1::shared_ptr<RandomNumberGenerator>(); //0;
   cached_default_allocator = std::tr1::shared_ptr<Allocator>();
   x509_state_obj = std::tr1::shared_ptr<X509_GlobalState>();
   ui = std::tr1::shared_ptr<UI>();
   }

/*************************************************
* Library_State Destructor                       *
*************************************************/
Library_State::~Library_State()
   {
   delete rng;

//   std::for_each(entropy_sources.begin(), entropy_sources.end(),
//                 del_fun<EntropySource>());
//   std::for_each(engines.begin(), engines.end(), del_fun<Engine>());
   entropy_sources.clear();
   engines.clear();

   cached_default_allocator.reset();

   for(u32bit j = 0; j != allocators.size(); ++j)
      {
      allocators[j]->destroy();
      }

//   std::for_each(locks.begin(), locks.end(),
//                 delete2nd<std::map<std::string, Mutex*>::value_type>);

   }

}
