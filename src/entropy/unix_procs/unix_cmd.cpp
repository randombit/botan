/*
* Unix Command Execution
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/unix_cmd.h>
#include <botan/parsing.h>
#include <botan/exceptn.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

namespace Botan {

namespace {

/**
* Attempt to execute the command
*/
void do_exec(const std::vector<std::string>& arg_list,
             const std::vector<std::string>& paths)
   {
   const u32bit args = arg_list.size() - 1;

   const char* arg1 = (args >= 1) ? arg_list[1].c_str() : 0;
   const char* arg2 = (args >= 2) ? arg_list[2].c_str() : 0;
   const char* arg3 = (args >= 3) ? arg_list[3].c_str() : 0;
   const char* arg4 = (args >= 4) ? arg_list[4].c_str() : 0;

   for(u32bit j = 0; j != paths.size(); j++)
      {
      const std::string full_path = paths[j] + "/" + arg_list[0];
      const char* fsname = full_path.c_str();
      ::execl(fsname, fsname, arg1, arg2, arg3, arg4, NULL);
      }
   }

}

/**
* Local information about the pipe
*/
struct pipe_wrapper
   {
   int fd;
   pid_t pid;
   pipe_wrapper() { fd = -1; pid = 0; }
   };

/**
* Read from the pipe
*/
u32bit DataSource_Command::read(byte buf[], u32bit length)
   {
   if(end_of_data())
      return 0;

   fd_set set;
   FD_ZERO(&set);
   FD_SET(pipe->fd, &set);

   struct ::timeval tv;
   tv.tv_sec = 0;
   tv.tv_usec = MAX_BLOCK_USECS;

   ssize_t got = 0;
   if(::select(pipe->fd + 1, &set, 0, 0, &tv) == 1)
      {
      if(FD_ISSET(pipe->fd, &set))
         got = ::read(pipe->fd, buf, length);
      }

   if(got <= 0)
      {
      shutdown_pipe();
      return 0;
      }

   return static_cast<u32bit>(got);
   }

/**
* Peek at the pipe contents
*/
u32bit DataSource_Command::peek(byte[], u32bit, u32bit) const
   {
   if(end_of_data())
      throw Invalid_State("DataSource_Command: Cannot peek when out of data");
   throw Stream_IO_Error("Cannot peek/seek on a command pipe");
   }

/**
* Check if we reached EOF
*/
bool DataSource_Command::end_of_data() const
   {
   return (pipe) ? false : true;
   }

/**
* Return the Unix file descriptor of the pipe
*/
int DataSource_Command::fd() const
   {
   if(!pipe)
      return -1;
   return pipe->fd;
   }

/**
* Return a human-readable ID for this stream
*/
std::string DataSource_Command::id() const
   {
   return "Unix command: " + arg_list[0];
   }

/**
* Create the pipe
*/
void DataSource_Command::create_pipe(const std::vector<std::string>& paths)
   {
   bool found_something = false;
   for(u32bit j = 0; j != paths.size(); j++)
      {
      const std::string full_path = paths[j] + "/" + arg_list[0];
      if(::access(full_path.c_str(), X_OK) == 0)
         {
         found_something = true;
         break;
         }
      }
   if(!found_something)
      return;

   int pipe_fd[2];
   if(::pipe(pipe_fd) != 0)
      return;

   pid_t pid = ::fork();

   if(pid == -1)
      {
      ::close(pipe_fd[0]);
      ::close(pipe_fd[1]);
      }
   else if(pid > 0)
      {
      pipe = new pipe_wrapper;
      pipe->fd = pipe_fd[0];
      pipe->pid = pid;
      ::close(pipe_fd[1]);
      }
   else
      {
      if(dup2(pipe_fd[1], STDOUT_FILENO) == -1)
         ::exit(127);
      if(close(pipe_fd[0]) != 0 || close(pipe_fd[1]) != 0)
         ::exit(127);
      if(close(STDERR_FILENO) != 0)
         ::exit(127);

      do_exec(arg_list, paths);
      ::exit(127);
      }
   }

/**
* Shutdown the pipe
*/
void DataSource_Command::shutdown_pipe()
   {
   if(pipe)
      {
      pid_t reaped = waitpid(pipe->pid, 0, WNOHANG);

      if(reaped == 0)
         {
         kill(pipe->pid, SIGTERM);

         struct ::timeval tv;
         tv.tv_sec = 0;
         tv.tv_usec = KILL_WAIT;
         select(0, 0, 0, 0, &tv);

         reaped = ::waitpid(pipe->pid, 0, WNOHANG);

         if(reaped == 0)
            {
            ::kill(pipe->pid, SIGKILL);
            do
               reaped = ::waitpid(pipe->pid, 0, 0);
            while(reaped == -1);
            }
         }

      ::close(pipe->fd);
      delete pipe;
      pipe = 0;
      }
   }

/**
* DataSource_Command Constructor
*/
DataSource_Command::DataSource_Command(const std::string& prog_and_args,
                                       const std::vector<std::string>& paths) :
   MAX_BLOCK_USECS(100000), KILL_WAIT(10000)
   {
   arg_list = split_on(prog_and_args, ' ');

   if(arg_list.size() == 0)
      throw Invalid_Argument("DataSource_Command: No command given");
   if(arg_list.size() > 5)
      throw Invalid_Argument("DataSource_Command: Too many args");

   pipe = 0;
   create_pipe(paths);
   }

/**
* DataSource_Command Destructor
*/
DataSource_Command::~DataSource_Command()
   {
   if(!end_of_data())
      shutdown_pipe();
   }

}
