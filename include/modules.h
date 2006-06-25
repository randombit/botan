/*************************************************
* Module Factory Header File                     *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_MODULE_FACTORIES_H__
#define BOTAN_MODULE_FACTORIES_H__

#include <vector>
#include <string>

namespace Botan {

/*************************************************
* Forward Declarations                           *
*************************************************/
class Mutex_Factory;
class Timer;
class EntropySource;
class Engine;
class Allocator;

namespace Modules {

/*************************************************
* Get the module objects                         *
*************************************************/
class Mutex_Factory* get_mutex_factory();
class Timer* get_timer();
std::vector<EntropySource*> get_entropy_sources();
std::vector<Engine*> get_engines();
std::vector<Allocator*> get_allocators();

}

}

#endif
