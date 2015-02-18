 /*
* Gather entropy by running various system commands in the hopes that
* some of the output cannot be guessed by a remote attacker.
*
* (C) 1999-2009,2013 Jack Lloyd
*     2012 Markus Wanner
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/unix_procs.h>
#include <botan/parsing.h>
#include <algorithm>
#include <atomic>

#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>

namespace Botan {

namespace {

std::string find_full_path_if_exists(const std::vector<std::string>& trusted_path,
                                     const std::string& proc)
   {
   for(auto dir : trusted_path)
      {
      const std::string full_path = dir + "/" + proc;
      if(::access(full_path.c_str(), X_OK) == 0)
         return full_path;
      }

   return "";
   }

size_t concurrent_processes(size_t user_request)
   {
   const size_t DEFAULT_CONCURRENT = 2;
   const size_t MAX_CONCURRENT = 8;

   if(user_request > 0 && user_request < MAX_CONCURRENT)
      return user_request;

   const long online_cpus = ::sysconf(_SC_NPROCESSORS_ONLN);

   if(online_cpus > 0)
      return static_cast<size_t>(online_cpus); // maybe fewer?

   return DEFAULT_CONCURRENT;
   }

}

/**
* Unix_EntropySource Constructor
*/
Unix_EntropySource::Unix_EntropySource(const std::vector<std::string>& trusted_path,
                                       size_t proc_cnt) :
   m_trusted_paths(trusted_path),
   m_concurrent(concurrent_processes(proc_cnt))
   {
   }

void UnixProcessInfo_EntropySource::poll(Entropy_Accumulator& accum)
   {
   static std::atomic<int> last_pid;

   int pid = ::getpid();

   accum.add(pid, 0.0);

   if(pid != last_pid)
      {
      last_pid = pid;
      accum.add(::getppid(), 0.0);
      accum.add(::getuid(),  0.0);
      accum.add(::getgid(),  0.0);
      accum.add(::getsid(0),  0.0);
      accum.add(::getpgrp(), 0.0);
      }

   struct ::rusage usage;
   ::getrusage(RUSAGE_SELF, &usage);
   accum.add(usage, 0.0);
   }

namespace {

void do_exec(const std::vector<std::string>& args)
   {
   // cleaner way to do this?
   const char* arg0 = (args.size() > 0) ? args[0].c_str() : nullptr;
   const char* arg1 = (args.size() > 1) ? args[1].c_str() : nullptr;
   const char* arg2 = (args.size() > 2) ? args[2].c_str() : nullptr;
   const char* arg3 = (args.size() > 3) ? args[3].c_str() : nullptr;
   const char* arg4 = (args.size() > 4) ? args[4].c_str() : nullptr;

   ::execl(arg0, arg0, arg1, arg2, arg3, arg4, NULL);
   }

}

void Unix_EntropySource::Unix_Process::spawn(const std::vector<std::string>& args)
   {
   shutdown();

   int pipe[2];
   if(::pipe(pipe) != 0)
      return;

   pid_t pid = ::fork();

   if(pid == -1)
      {
      ::close(pipe[0]);
      ::close(pipe[1]);
      }
   else if(pid > 0) // in parent
      {
      m_pid = pid;
      m_fd = pipe[0];
      ::close(pipe[1]);
      }
   else // in child
      {
      if(::dup2(pipe[1], STDOUT_FILENO) == -1)
         ::exit(127);
      if(::close(pipe[0]) != 0 || ::close(pipe[1]) != 0)
         ::exit(127);
      if(close(STDERR_FILENO) != 0)
         ::exit(127);

      do_exec(args);
      ::exit(127);
      }
   }

void Unix_EntropySource::Unix_Process::shutdown()
   {
   if(m_pid == -1)
      return;

   ::close(m_fd);
   m_fd = -1;

   pid_t reaped = waitpid(m_pid, nullptr, WNOHANG);

   if(reaped == 0)
      {
      /*
      * Child is still alive - send it SIGTERM, sleep for a bit and
      * try to reap again, if still alive send SIGKILL
      */
      kill(m_pid, SIGTERM);

      struct ::timeval tv;
      tv.tv_sec = 0;
      tv.tv_usec = 1000;
      select(0, nullptr, nullptr, nullptr, &tv);

      reaped = ::waitpid(m_pid, nullptr, WNOHANG);

      if(reaped == 0)
         {
         ::kill(m_pid, SIGKILL);
         do
            reaped = ::waitpid(m_pid, nullptr, 0);
         while(reaped == -1);
         }
      }

   m_pid = -1;
   }

const std::vector<std::string>& Unix_EntropySource::next_source()
   {
   const auto& src = m_sources.at(m_sources_idx);
   m_sources_idx = (m_sources_idx + 1) % m_sources.size();
   return src;
   }

void Unix_EntropySource::poll(Entropy_Accumulator& accum)
   {
   // refuse to run setuid or setgid, or as root
   if((getuid() != geteuid()) || (getgid() != getegid()) || (geteuid() == 0))
      return;

   std::lock_guard<std::mutex> lock(m_mutex);

   if(m_sources.empty())
      {
      auto sources = get_default_sources();

      for(auto src : sources)
         {
         const std::string path = find_full_path_if_exists(m_trusted_paths, src[0]);
         if(path != "")
            {
            src[0] = path;
            m_sources.push_back(src);
            }
         }
      }

   if(m_sources.empty())
      return; // still empty, really nothing to try

   const size_t MS_WAIT_TIME = 32;
   const double ENTROPY_ESTIMATE = 1.0 / 1024;

   secure_vector<byte>& io_buffer = accum.get_io_buffer(4*1024); // page

   while(!accum.polling_goal_achieved())
      {
      while(m_procs.size() < m_concurrent)
         m_procs.emplace_back(Unix_Process(next_source()));

      fd_set read_set;
      FD_ZERO(&read_set);

      std::vector<int> fds;

      for(auto& proc : m_procs)
         {
         int fd = proc.fd();
         if(fd > 0)
            {
            fds.push_back(fd);
            FD_SET(fd, &read_set);
            }
         }

      if(fds.empty())
         break;

      const int max_fd = *std::max_element(fds.begin(), fds.end());

      struct ::timeval timeout;
      timeout.tv_sec = (MS_WAIT_TIME / 1000);
      timeout.tv_usec = (MS_WAIT_TIME % 1000) * 1000;

      if(::select(max_fd + 1, &read_set, nullptr, nullptr, &timeout) < 0)
         return; // or continue?

      for(auto& proc : m_procs)
         {
         int fd = proc.fd();

         if(FD_ISSET(fd, &read_set))
            {
            const ssize_t got = ::read(fd, &io_buffer[0], io_buffer.size());
            if(got > 0)
               accum.add(&io_buffer[0], got, ENTROPY_ESTIMATE);
            else
               proc.spawn(next_source());
            }
         }
      }
   }

}
