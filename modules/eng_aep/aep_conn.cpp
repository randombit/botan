/*************************************************
* AEP Connection Management Source File          *
* (C) 1999-2007 The Botan Project                *
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

/*************************************************
* Close all currently open connections           *
*************************************************/
void AEP_Connection::close_all_connections()
   {
   Mutex* mutex = global_state().get_named_mutex("aep");

   mutex->lock();
   for(u32bit j = 0; j != pool.size(); j++)
      AEP::AEP_CloseConnection(pool[j].id);
   pool.clear();
   mutex->unlock();
   }

/*************************************************
* Get a new connection handle                    *
*************************************************/
AEP_Connection::AEP_Connection()
   {
   Named_Mutex_Holder lock("aep");

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
   Named_Mutex_Holder lock("aep");

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
