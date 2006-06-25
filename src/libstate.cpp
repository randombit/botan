/*************************************************
* Library Internal/Global State Source File      *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/libstate.h>
#include <botan/engine.h>
#include <botan/x509stat.h>
#include <botan/stl_util.h>
#include <botan/mutex.h>
#include <botan/timers.h>
#include <botan/charset.h>

namespace Botan {

/*************************************************
* Botan's global state                           *
*************************************************/
namespace {

Library_State* global_lib_state = 0;

}

Library_State& global_state()
   {
   if(!global_lib_state)
      throw Invalid_State("Library was not intialized correctly");
   return (*global_lib_state);
   }

void set_global_state(Library_State* new_state)
   {
   delete swap_global_state(new_state);
   }

Library_State* swap_global_state(Library_State* new_state)
   {
   Library_State* old_state = global_lib_state;
   global_lib_state = new_state;
   return old_state;
   }

namespace {

/*************************************************
* Named Mutex Holder                             *
*************************************************/
class Named_Mutex_Holder
   {
   public:
      Named_Mutex_Holder(const std::map<std::string, Mutex*>& mutexes,
                         const std::string& name)
         {
         mux = search_map<std::string, Mutex*>(mutexes, name, 0);

         if(!mux)
            throw Invalid_Argument("Named_Mutex_Holder: mutex not found");

         mux->lock();
         }

      ~Named_Mutex_Holder() { mux->unlock(); }
   private:
      Mutex* mux;
   };

}

/*************************************************
* Increment the Engine iterator                  *
*************************************************/
Engine* Library_State::Engine_Iterator::next()
   {
   return lib.get_engine_n(n++);
   }

/*************************************************
* Get a new mutex object                         *
*************************************************/
Mutex* Library_State::get_mutex() const
   {
   return mutex_factory->make();
   }

/*************************************************
* Get an allocator by its name                   *
*************************************************/
Allocator* Library_State::get_allocator(const std::string& type) const
   {
   Named_Mutex_Holder lock(locks, "allocator");

   if(type != "")
      return search_map<std::string, Allocator*>(alloc_factory, type, 0);

   if(!cached_default_allocator)
      {
      const std::string key_name = "conf/base/default_allocator";

      Named_Mutex_Holder lock(locks, "settings");
      std::string chosen = search_map(settings, key_name);

      if(chosen == "")
         chosen = "malloc";

      cached_default_allocator =
         search_map<std::string, Allocator*>(alloc_factory, chosen, 0);
      }

   return cached_default_allocator;
   }

/*************************************************
* Create a new name to object mapping            *
*************************************************/
void Library_State::add_allocator(const std::string& type,
                                  Allocator* allocator)
   {
   Named_Mutex_Holder lock(locks, "allocator");

   allocator->init();
   if(alloc_factory[type])
      delete alloc_factory[type];
   alloc_factory[type] = allocator;
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
   Named_Mutex_Holder lock(locks, "rng");

   delete rng;
   rng = new_rng;
   }

/*************************************************
* Get bytes from the global PRNG                 *
*************************************************/
void Library_State::randomize(byte out[], u32bit length)
   {
   Named_Mutex_Holder lock(locks, "rng");

   rng->randomize(out, length);
   }

/*************************************************
* Add a new entropy source to use                *
*************************************************/
void Library_State::add_entropy_source(EntropySource* src, bool last_in_list)
   {
   Named_Mutex_Holder lock(locks, "rng");

   if(last_in_list)
      entropy_sources.push_back(src);
   else
      entropy_sources.insert(entropy_sources.begin(), src);
   }

/*************************************************
* Add some bytes of entropy to the global PRNG   *
*************************************************/
void Library_State::add_entropy(const byte in[], u32bit length)
   {
   Named_Mutex_Holder lock(locks, "rng");

   rng->add_entropy(in, length);
   }

/*************************************************
* Add some bytes of entropy to the global PRNG   *
*************************************************/
void Library_State::add_entropy(EntropySource& source, bool slow_poll)
   {
   Named_Mutex_Holder lock(locks, "rng");

   rng->add_entropy(source, slow_poll);
   }

/*************************************************
* Gather entropy for our PRNG object             *
*************************************************/
u32bit Library_State::seed_prng(bool slow_poll, u32bit bits_to_get)
   {
   Named_Mutex_Holder lock(locks, "rng");

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
* Set a named option                             *
*************************************************/
void Library_State::set_option(const std::string& section,
                               const std::string& name,
                               const std::string& value,
                               bool overwrite)
   {
   Named_Mutex_Holder lock(locks, "settings");

   std::map<std::string, std::string>::const_iterator i = settings.find(name);

   if(overwrite || i == settings.end() || i->second == "")
      {
      const std::string full_name = section + "/" + name;
      settings[full_name] = value;

      if(full_name == "base/default_allocator")
         cached_default_allocator = 0;
      }
   }

/*************************************************
* Get the value of the named option              *
*************************************************/
std::string Library_State::get_option(const std::string& section,
                                      const std::string& name) const
   {
   Named_Mutex_Holder lock(locks, "settings");

   return search_map<std::string, std::string>(settings,
                                               section + "/" + name, "");
   }

/*************************************************
* See if a particular option has been set        *
*************************************************/
bool Library_State::option_set(const std::string& section,
                               const std::string& name) const
   {
   Named_Mutex_Holder lock(locks, "settings");

   return search_map(settings, section + "/" + name, false, true);
   }

/*************************************************
* Get an engine out of the list                  *
*************************************************/
Engine* Library_State::get_engine_n(u32bit n) const
   {
   Named_Mutex_Holder lock(locks, "engine");

   if(n >= engines.size())
      return 0;
   return engines[n];
   }

/*************************************************
* Add a new engine to the list                   *
*************************************************/
void Library_State::add_engine(Engine* engine)
   {
   Named_Mutex_Holder lock(locks, "engine");
   engines.push_back(engine);
   }

/*************************************************
* Set the character set transcoder object        *
*************************************************/
void Library_State::set_transcoder(class Charset_Transcoder* transcoder)
   {
   if(this->transcoder)
      delete this->transcoder;
   this->transcoder = transcoder;
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
void Library_State::set_x509_state(X509_GlobalState* new_x509_state_obj)
   {
   delete x509_state_obj;
   x509_state_obj = new_x509_state_obj;
   }

/*************************************************
* Set the X509 global state class                *
*************************************************/
X509_GlobalState& Library_State::x509_state() const
   {
   if(!x509_state_obj)
      x509_state_obj = new X509_GlobalState();

   return (*x509_state_obj);
   }

/*************************************************
* Library_State Constructor                      *
*************************************************/
Library_State::Library_State(Mutex_Factory* mutex_factory, Timer* timer)
   {
   if(!mutex_factory)
      mutex_factory = new Mutex_Factory;
   if(!timer)
      timer = new Timer;

   this->mutex_factory = mutex_factory;
   this->timer = timer;
   this->transcoder = 0;

   locks["settings"] = get_mutex();
   locks["allocator"] = get_mutex();
   locks["rng"] = get_mutex();
   locks["engine"] = get_mutex();
   rng = 0;
   cached_default_allocator = 0;
   x509_state_obj = 0;

   set_default_policy();
   }

/*************************************************
* Library_State Destructor                       *
*************************************************/
Library_State::~Library_State()
   {
   delete x509_state_obj;
   delete transcoder;
   for(u32bit j = 0; j != entropy_sources.size(); ++j)
      delete entropy_sources[j];

   delete rng;

   for(u32bit j = 0; j != engines.size(); ++j)
      delete engines[j];

   cached_default_allocator = 0;
   for(std::map<std::string, Allocator*>::iterator j = alloc_factory.begin();
       j != alloc_factory.end(); ++j)
      {
      j->second->destroy();
      delete j->second;
      }

   delete mutex_factory;
   delete timer;

   for(std::map<std::string, Mutex*>::iterator j = locks.begin();
       j != locks.end(); ++j)
      delete j->second;
   }

}
