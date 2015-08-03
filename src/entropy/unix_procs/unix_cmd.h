/*
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
   /**
   * @param n is the name and arguments of what we are going run
   * @param p is the priority level (lower prio numbers get polled first)
   */
   Unix_Program(const char* n, size_t p)
      { name_and_args = n; priority = p; working = true; }

   /**
   * The name and arguments for this command
   */
   std::string name_and_args;

   /**
   * Priority: we scan from low to high
   */
   size_t priority;

   /**
   * Does this source seem to be working?
   */
   bool working;
   };

/**
* Command Output DataSource
*/
class DataSource_Command : public DataSource
   {
   public:
      size_t read(byte[], size_t);
      size_t peek(byte[], size_t, size_t) const;
      bool check_available(size_t n);
      bool end_of_data() const;
      std::string id() const;

      int fd() const;

      DataSource_Command(const std::string&,
                         const std::vector<std::string>& paths);
      ~DataSource_Command();
   private:
      void create_pipe(const std::vector<std::string>&);
      void shutdown_pipe();

      const size_t MAX_BLOCK_USECS, KILL_WAIT;

      std::vector<std::string> arg_list;
      struct pipe_wrapper* pipe;
   };

}

#endif
