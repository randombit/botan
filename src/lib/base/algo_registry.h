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

namespace Botan {

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
         std::unique_lock<std::mutex> lock(m_mutex);
         m_algo_info[name].add_provider(provider, fn, pref);
         }

      std::vector<std::string> providers_of(const Spec& spec)
         {
         std::unique_lock<std::mutex> lock(m_mutex);
         auto i = m_algo_info.find(spec.algo_name());
         if(i != m_algo_info.end())
            return i->second.providers();
         return std::vector<std::string>();
         }

      T* make(const Spec& spec, const std::string& provider = "")
         {
         maker_fn maker = find_maker(spec, provider);

         try
            {
            return maker(spec);
            }
         catch(std::exception& e)
            {
            throw std::runtime_error("Creating '" + spec.as_string() + "' failed: " + e.what());
            }
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
      Algo_Registry() {}

      maker_fn find_maker(const Spec& spec, const std::string& provider)
         {
         std::unique_lock<std::mutex> lock(m_mutex);
         return m_algo_info[spec.algo_name()].get_maker(provider);
         }

      struct Algo_Info
         {
         public:
            void add_provider(const std::string& provider, maker_fn fn, byte pref = 128)
               {
               if(m_maker_fns.count(provider) > 0)
                  throw std::runtime_error("Duplicated registration of '" + provider + "'");

               m_maker_fns[provider] = std::make_pair(pref, fn);
               }

            std::vector<std::string> providers() const
               {
               std::vector<std::string> v;
               for(auto&& k : m_maker_fns)
                  v.push_back(k.first);
               return v;
               }

            void set_pref(const std::string& provider, byte val)
               {
               m_maker_fns[provider].first = val;
               }

            maker_fn get_maker(const std::string& req_provider)
               {
               maker_fn null_result = [](const Spec&) { return nullptr; };

               if(req_provider != "")
                  {
                  // find one explicit provider requested by user or fail
                  auto i = m_maker_fns.find(req_provider);
                  if(i != m_maker_fns.end())
                     return i->second.second;
                  return null_result;
                  }

               size_t pref = 255;
               maker_fn result = null_result;

               for(auto&& i : m_maker_fns)
                  {
                  if(i.second.first < pref)
                     {
                     pref = i.second.first;
                     result = i.second.second;
                     }
                  }

               return result;
               }
         private:
            std::unordered_map<std::string, std::pair<byte, maker_fn>> m_maker_fns; // provider -> (pref, creator fn)
         };

      std::mutex m_mutex;
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
make_new_T(const typename Algo_Registry<T>::Spec&) { return new T; }

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

#define BOTAN_REGISTER_TYPE(T, type, name, maker, provider, pref)        \
   namespace { Algo_Registry<T>::Add g_ ## type ## _reg(name, maker, provider, pref); }

#define BOTAN_REGISTER_TYPE_COND(cond, T, type, name, maker, provider, pref) \
   namespace { Algo_Registry<T>::Add g_ ## type ## _reg(cond, name, maker, provider, pref); }

#define BOTAN_REGISTER_NAMED_T(T, name, type, maker)                 \
   BOTAN_REGISTER_TYPE(T, type, name, maker, "builtin", 128)

#define BOTAN_REGISTER_T(T, type, maker)                                \
   BOTAN_REGISTER_TYPE(T, type, #type, maker, "builtin", 128)

#define BOTAN_REGISTER_T_NOARGS(T, type) \
   BOTAN_REGISTER_TYPE(T, type, #type, make_new_T<type>, "builtin", 128)
#define BOTAN_REGISTER_T_1LEN(T, type, def) \
   BOTAN_REGISTER_TYPE(T, type, #type, (make_new_T_1len<type,def>), "builtin", 128)

#define BOTAN_REGISTER_NAMED_T_NOARGS(T, type, name, provider) \
   BOTAN_REGISTER_TYPE(T, type, name, make_new_T<type>, provider, 128)
#define BOTAN_COND_REGISTER_NAMED_T_NOARGS(cond, T, type, name, provider, pref) \
   BOTAN_REGISTER_TYPE_COND(cond, T, type, name, make_new_T<type>, provider, pref)

#define BOTAN_REGISTER_NAMED_T_2LEN(T, type, name, provider, len1, len2) \
   BOTAN_REGISTER_TYPE(T, type, name, (make_new_T_2len<type,len1,len2>), provider, 128)

// TODO move elsewhere:
#define BOTAN_REGISTER_TRANSFORM(name, maker) BOTAN_REGISTER_T(Transform, name, maker)
#define BOTAN_REGISTER_TRANSFORM_NOARGS(name) BOTAN_REGISTER_T_NOARGS(Transform, name)

}

#endif
