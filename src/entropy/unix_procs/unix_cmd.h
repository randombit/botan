/**
* Unix Command Execution
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_UNIX_CMD_H__
#define BOTAN_UNIX_CMD_H__

#include <botan/types.h>
#include <botan/data_src.h>
#include <string>
#include <vector>

namespace Botan {

/**
* Unix Program Info
*/
struct Unix_Program
   {
   Unix_Program(const char* n, u32bit p)
      { name_and_args = n; priority = p; working = true; }

   std::string name_and_args;
   u32bit priority;
   bool working;
   };

/**
* Command Output DataSource
*/
class BOTAN_DLL DataSource_Command : public DataSource
   {
   public:
      u32bit read(byte[], u32bit);
      u32bit peek(byte[], u32bit, u32bit) const;
      bool end_of_data() const;
      std::string id() const;

      int fd() const;

      DataSource_Command(const std::string&,
                         const std::vector<std::string>& paths);
      ~DataSource_Command();
   private:
      void create_pipe(const std::vector<std::string>&);
      void shutdown_pipe();

      const u32bit MAX_BLOCK_USECS, KILL_WAIT;

      std::vector<std::string> arg_list;
      struct pipe_wrapper* pipe;
   };

}

#endif
