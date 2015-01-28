/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/transform.h>
#include <botan/algo_registry.h>

namespace Botan {

Transform* get_transform(const std::string& specstr,
                         const std::string& provider,
                         const std::string& dirstr)
   {
   Algo_Registry<Transform>::Spec spec(specstr, dirstr);
   return Algo_Registry<Transform>::global_registry().make(spec, provider);
   }

}
