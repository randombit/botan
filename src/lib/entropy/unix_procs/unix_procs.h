/*
* Unix EntropySource
* (C) 1999-2009,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ENTROPY_SRC_UNIX_H__
#define BOTAN_ENTROPY_SRC_UNIX_H__

#include <botan/entropy_src.h>
#include <vector>
#include <botan/mutex.h>

namespace Botan {

/**
* Entropy source for generic Unix. Runs various programs trying to
* gather data hard for a remote attacker to guess. Probably not too
* effective against local attackers as they can sample from the same
* distribution.
*/
class Unix_EntropySource final : public Entropy_Source
   {
   public:
      std::string name() const override { return "unix_procs"; }

      size_t poll(RandomNumberGenerator& rng) override;

      /**
      * @param trusted_paths is a list of directories that are assumed
      *        to contain only 'safe' binaries. If an attacker can write
      *        an executable to one of these directories then we will
      *        run arbitrary code.
      * @param proc_count number of concurrent processes executing,
      * when set to zero, number of processors is used
      */
      Unix_EntropySource(const std::vector<std::string>& trusted_paths,
                         size_t proc_count = 0);
   private:
      static std::vector<std::vector<std::string>> get_default_sources();

      class Unix_Process
         {
         public:
            int fd() const { return m_fd; }

            void spawn(const std::vector<std::string>& args);
            void shutdown();

            Unix_Process() {}

            Unix_Process(const std::vector<std::string>& args) { spawn(args); }

            ~Unix_Process() { shutdown(); }

            Unix_Process(Unix_Process&& other)
               {
               std::swap(m_fd, other.m_fd);
               std::swap(m_pid, other.m_pid);
               }

            Unix_Process(const Unix_Process&) = delete;
            Unix_Process& operator=(const Unix_Process&) = delete;
         private:
            int m_fd = -1;
            int m_pid = -1;
         };

      const std::vector<std::string>& next_source();

      mutex_type m_mutex;
      const std::vector<std::string> m_trusted_paths;
      const size_t m_concurrent;

      std::vector<std::vector<std::string>> m_sources;
      size_t m_sources_idx = 0;

      std::vector<Unix_Process> m_procs;
      secure_vector<byte> m_buf;
   };

class UnixProcessInfo_EntropySource final : public Entropy_Source
   {
   public:
      std::string name() const override { return "proc_info"; }

      size_t poll(RandomNumberGenerator& rng) override;
   };

}

#endif
