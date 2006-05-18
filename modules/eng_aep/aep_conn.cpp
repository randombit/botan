/*************************************************
* AEP Connection Management Source File          *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/aep_conn.h>
#include <botan/libstate.h>
#include <botan/parsing.h>
#include <botan/hw_aep.h>

namespace Botan {

/*************************************************
* Persistent connection pool                     *
*************************************************/
std::vector<AEP_Connection::Connection_Info> AEP_Connection::pool;
Mutex* AEP_Connection::guard = 0;

/*************************************************
* Close all currently open connections           *
*************************************************/
void AEP_Connection::close_all_connections()
   {
   guard->lock();
   for(u32bit j = 0; j != pool.size(); j++)
      AEP::AEP_CloseConnection(pool[j].id);
   pool.clear();
   guard->unlock();
   delete guard;
   guard = 0;
   }

/*************************************************
* Get a new connection handle                    *
*************************************************/
AEP_Connection::AEP_Connection()
   {
   // FIXME: race condition
   if(!guard)
      guard = global_state().get_mutex();

   Mutex_Holder lock(guard);

   this_connection = 0;

   for(u32bit j = 0; j != pool.size(); j++)
      {
      if(pool[j].in_use)
         continue;

      pool[j].in_use = true;
      this_connection = pool[j].id;
      }

   if(this_connection == 0)
      {
      Connection_Info new_conn;

      u32bit retval = AEP::AEP_OpenConnection(&new_conn.id);
      if(retval != 0)
         throw Stream_IO_Error("AEP_OpenConnection failed");
      new_conn.in_use = true;

      if(pool.size() < MAX_CACHED_CONNECTIONS)
         pool.push_back(new_conn);

      this_connection = new_conn.id;
      }
   }

/*************************************************
* Free a connection handle                       *
*************************************************/
AEP_Connection::~AEP_Connection()
   {
   Mutex_Holder lock(guard);

   for(u32bit j = 0; j != pool.size(); j++)
      {
      if(pool[j].id != this_connection)
         continue;

      pool[j].in_use = false;
      return;
      }

   int retval = AEP::AEP_CloseConnection(this_connection);
   if(retval != 0)
      throw Exception("AEP_CloseConnection returned " + to_string(retval));
   }

}
