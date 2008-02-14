/*************************************************
* AEP Connection Management Header File          *
* (C) 1999-2008 The Botan Project                *
*************************************************/

#ifndef BOTAN_EXT_AEP_CONNECTION_H__
#define BOTAN_EXT_AEP_CONNECTION_H__

#include <botan/eng_aep.h>
#include <botan/mutex.h>

namespace Botan {

/*************************************************
* AEP Connection                                 *
*************************************************/
class AEP_Connection
   {
   public:
      operator u32bit () { return this_connection; }

      static void close_all_connections();

      AEP_Connection();
      ~AEP_Connection();
   private:
      struct Connection_Info { u32bit id; bool in_use; };

      static const u32bit MAX_CACHED_CONNECTIONS = 8;
      static std::vector<Connection_Info> pool;

      u32bit this_connection;
   };

}

#endif
