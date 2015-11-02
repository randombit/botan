/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ALGO_REGISTRY_H__
#define BOTAN_ALGO_REGISTRY_H__

#include <botan/types.h>
#include <functional>
#include <stdexcept>
#include <mutex>
#include <vector>
#include <map>
#include <string>
#include <unordered_map>

#if defined(_MSC_VER) && (_MSC_VER <= 1800)
    #define NOMINMAX 1
    #define WIN32_LEAN_AND_MEAN 1
    #include <Windows.h>
#endif

namespace Botan {

#if defined(_MSC_VER) && (_MSC_VER <= 1800)
class Windows_Lock
   {
   public:
       Windows_Lock(CRITICAL_SECTION& cs): m_cs(cs)
          {
          EnterCriticalSection(&m_cs);
          }
          
       ~Windows_Lock()
          {
          LeaveCriticalSection(&m_cs);
          }
    private:
        CRITICAL_SECTION&   m_cs;
   };

   #define ALGO_REGISTRY_LOCK(_x) Windows_Lock lock(_x)
#else
   #define ALGO_REGISTRY_LOCK(_x) std::unique_lock<std::mutex> lock(_x)
#endif

template<typename T>
class Algo_Registry
   {
   public:
      typedef typename T::Spec Spec;

      typedef std::function<T* (const Spec&)> maker_fn;

      static Algo_Registry<T>& global_registry()
         {
         static Algo_Registry<T> g_registry;
         return g_registry;
         }

      void add(const std::string& name, const std::string& provider, maker_fn fn, byte pref)
         {
         ALGO_REGISTRY_LOCK(m_mutex);
         if(!m_algo_info[name].add_provider(provider, fn, pref))
            throw std::runtime_error("Duplicated registration of " + name + "/" + provider);
         }

      std::vector<std::string> providers_of(const Spec& spec)
         {
         ALGO_REGISTRY_LOCK(m_mutex);
         auto i = m_algo_info.find(spec.algo_name());
         if(i != m_algo_info.end())
            return i->second.providers();
         return std::vector<std::string>();
         }

      void set_provider_preference(const Spec& spec, const std::string& provider, byte pref)
         {
         ALGO_REGISTRY_LOCK(m_mutex);
         auto i = m_algo_info.find(spec.algo_name());
         if(i != m_algo_info.end())
            i->second.set_pref(provider, pref);
         }

      T* make(const Spec& spec, const std::string& provider = "")
         {
         const std::vector<maker_fn> makers = get_makers(spec, provider);

         try
            {
            for(auto&& maker : makers)
               {
               if(T* t = maker(spec))
                  return t;
               }
            }
         catch(std::exception& e)
            {
            throw std::runtime_error("Creating '" + spec.as_string() + "' failed: " + e.what());
            }

         return nullptr;
         }

      class Add
         {
         public:
            Add(const std::string& basename, maker_fn fn, const std::string& provider, byte pref)
               {
               Algo_Registry<T>::global_registry().add(basename, provider, fn, pref);
               }

            Add(bool cond, const std::string& basename, maker_fn fn, const std::string& provider, byte pref)
               {
               if(cond)
                  Algo_Registry<T>::global_registry().add(basename, provider, fn, pref);
               }
         };

   private:
      Algo_Registry()
         {
#if defined(_MSC_VER) && (_MSC_VER <= 1800)
         InitializeCriticalSection(&m_mutex);
#endif
         }
         
#if defined(_MSC_VER) && (_MSC_VER <= 1800)
      ~Algo_Registry()
         {
         DeleteCriticalSection(&m_mutex);
         }
#endif

      std::vector<maker_fn> get_makers(const Spec& spec, const std::string& provider)
         {
         ALGO_REGISTRY_LOCK(m_mutex);
         return m_algo_info[spec.algo_name()].get_makers(provider);
         }

      struct Algo_Info
         {
         public:
            bool add_provider(const std::string& provider, maker_fn fn, byte pref)
               {
               if(m_maker_fns.count(provider) > 0)
                  return false;

               m_maker_fns[provider] = fn;
               m_prefs.insert(std::make_pair(pref, provider));
               return true;
               }

            std::vector<std::string> providers() const
               {
               std::vector<std::string> v;
               for(auto&& k : m_prefs)
                  v.push_back(k.second);
               return v;
               }

            void set_pref(const std::string& provider, byte pref)
               {
               auto i = m_prefs.begin();
               while(i != m_prefs.end())
                  {
                  if(i->second == provider)
                     i = m_prefs.erase(i);
                  else
                     ++i;
                  }
               m_prefs.insert(std::make_pair(pref, provider));
               }

            std::vector<maker_fn> get_makers(const std::string& req_provider)
               {
               std::vector<maker_fn> r;

               if(req_provider != "")
                  {
                  // find one explicit provider requested by user or fail
                  auto i = m_maker_fns.find(req_provider);
                  if(i != m_maker_fns.end())
                     r.push_back(i->second);
                  }
               else
                  {
                  for(auto&& pref : m_prefs)
                     r.push_back(m_maker_fns[pref.second]);
                  }

               return r;
               }
         private:
            std::multimap<byte, std::string, std::greater<byte>> m_prefs;
            std::unordered_map<std::string, maker_fn> m_maker_fns;
         };

#if defined(_MSC_VER) && (_MSC_VER <= 1800)
      CRITICAL_SECTION m_mutex;
#else
      std::mutex m_mutex;
#endif
      std::unordered_map<std::string, Algo_Info> m_algo_info;
   };

template<typename T> T*
make_a(const typename T::Spec& spec, const std::string provider = "")
   {
   return Algo_Registry<T>::global_registry().make(spec, provider);
   }

template<typename T> std::vector<std::string> providers_of(const typename T::Spec& spec)
   {
   return Algo_Registry<T>::global_registry().providers_of(spec);
   }

template<typename T> T*
make_new_T(const typename Algo_Registry<T>::Spec& spec)
   {
   if(spec.arg_count() == 0)
      return new T;
   return nullptr;
   }

template<typename T, size_t DEF_VAL> T*
make_new_T_1len(const typename Algo_Registry<T>::Spec& spec)
   {
   return new T(spec.arg_as_integer(0, DEF_VAL));
   }

template<typename T, size_t DEF1, size_t DEF2> T*
make_new_T_2len(const typename Algo_Registry<T>::Spec& spec)
   {
   return new T(spec.arg_as_integer(0, DEF1), spec.arg_as_integer(1, DEF2));
   }

template<typename T> T*
make_new_T_1str(const typename Algo_Registry<T>::Spec& spec, const std::string& def)
   {
   return new T(spec.arg(0, def));
   }

template<typename T> T*
make_new_T_1str_req(const typename Algo_Registry<T>::Spec& spec)
   {
   return new T(spec.arg(0));
   }

template<typename T, typename X> T*
make_new_T_1X(const typename Algo_Registry<T>::Spec& spec)
   {
   std::unique_ptr<X> x(Algo_Registry<X>::global_registry().make(spec.arg(0)));
   if(!x)
      throw std::runtime_error(spec.arg(0));
   return new T(x.release());
   }

// Append to macros living outside of functions, so that invocations must end with a semicolon.
// The struct is only declared to force the semicolon, it is never defined.
#define BOTAN_FORCE_SEMICOLON struct BOTAN_DUMMY_STRUCT

#define BOTAN_REGISTER_TYPE(T, type, name, maker, provider, pref)        \
   namespace { Algo_Registry<T>::Add g_ ## type ## _reg(name, maker, provider, pref); } \
   BOTAN_FORCE_SEMICOLON

#define BOTAN_REGISTER_TYPE_COND(cond, T, type, name, maker, provider, pref) \
   namespace { Algo_Registry<T>::Add g_ ## type ## _reg(cond, name, maker, provider, pref); } \
   BOTAN_FORCE_SEMICOLON

#define BOTAN_DEFAULT_ALGORITHM_PRIO 100
#define BOTAN_SIMD_ALGORITHM_PRIO    110

#define BOTAN_REGISTER_NAMED_T(T, name, type, maker)                 \
   BOTAN_REGISTER_TYPE(T, type, name, maker, "base", BOTAN_DEFAULT_ALGORITHM_PRIO)

#define BOTAN_REGISTER_T(T, type, maker)                                \
   BOTAN_REGISTER_TYPE(T, type, #type, maker, "base", BOTAN_DEFAULT_ALGORITHM_PRIO)

#define BOTAN_REGISTER_T_NOARGS(T, type) \
   BOTAN_REGISTER_TYPE(T, type, #type, make_new_T<type>, "base", BOTAN_DEFAULT_ALGORITHM_PRIO)
#define BOTAN_REGISTER_T_1LEN(T, type, def) \
   BOTAN_REGISTER_TYPE(T, type, #type, (make_new_T_1len<type,def>), "base", BOTAN_DEFAULT_ALGORITHM_PRIO)

#define BOTAN_REGISTER_NAMED_T_NOARGS(T, type, name, provider) \
   BOTAN_REGISTER_TYPE(T, type, name, make_new_T<type>, provider, BOTAN_DEFAULT_ALGORITHM_PRIO)
#define BOTAN_COND_REGISTER_NAMED_T_NOARGS(cond, T, type, name, provider, pref) \
   BOTAN_REGISTER_TYPE_COND(cond, T, type, name, make_new_T<type>, provider, pref)

#define BOTAN_REGISTER_NAMED_T_2LEN(T, type, name, provider, len1, len2) \
   BOTAN_REGISTER_TYPE(T, type, name, (make_new_T_2len<type,len1,len2>), provider, BOTAN_DEFAULT_ALGORITHM_PRIO)

// TODO move elsewhere:
#define BOTAN_REGISTER_TRANSFORM(name, maker) BOTAN_REGISTER_T(Transform, name, maker)
#define BOTAN_REGISTER_TRANSFORM_NOARGS(name) BOTAN_REGISTER_T_NOARGS(Transform, name)

}

#endif
