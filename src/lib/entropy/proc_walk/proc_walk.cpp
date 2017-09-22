/*
* Entropy source based on reading files in /proc on the assumption
* that a remote attacker will have difficulty guessing some of them.
*
* (C) 1999-2008,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/proc_walk.h>
#include <deque>

#ifndef _POSIX_C_SOURCE
  #define _POSIX_C_SOURCE 199309
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>

namespace Botan {

namespace {

class Directory_Walker final : public File_Descriptor_Source
   {
   public:
      explicit Directory_Walker(const std::string& root) :
         m_cur_dir(std::make_pair<DIR*, std::string>(nullptr, ""))
         {
         if(DIR* root_dir = ::opendir(root.c_str()))
            m_cur_dir = std::make_pair(root_dir, root);
         }

      ~Directory_Walker()
         {
         if(m_cur_dir.first)
            ::closedir(m_cur_dir.first);
         }

      int next_fd() override;
   private:
      std::pair<struct dirent*, std::string> get_next_dirent();

      std::pair<DIR*, std::string> m_cur_dir;
      std::deque<std::string> m_dirlist;
   };

std::pair<struct dirent*, std::string> Directory_Walker::get_next_dirent()
   {
   while(m_cur_dir.first)
      {
      if(struct dirent* dir = ::readdir(m_cur_dir.first))
         return std::make_pair(dir, m_cur_dir.second);

      ::closedir(m_cur_dir.first);
      m_cur_dir = std::make_pair<DIR*, std::string>(nullptr, "");

      while(!m_dirlist.empty() && !m_cur_dir.first)
         {
         const std::string next_dir_name = m_dirlist[0];
         m_dirlist.pop_front();

         if(DIR* next_dir = ::opendir(next_dir_name.c_str()))
            m_cur_dir = std::make_pair(next_dir, next_dir_name);
         }
      }

   return std::make_pair<struct dirent*, std::string>(nullptr, ""); // nothing left
   }

int Directory_Walker::next_fd()
   {
   while(true)
      {
      std::pair<struct dirent*, std::string> entry = get_next_dirent();

      if(!entry.first)
         break; // no more dirs

      const std::string filename = entry.first->d_name;

      if(filename == "." || filename == "..")
         continue;

      const std::string full_path = entry.second + "/" + filename;

      struct stat stat_buf;
      if(::lstat(full_path.c_str(), &stat_buf) == -1)
         continue;

      if(S_ISDIR(stat_buf.st_mode))
         {
         m_dirlist.push_back(full_path);
         }
      else if(S_ISREG(stat_buf.st_mode) && (stat_buf.st_mode & S_IROTH))
         {
         int fd = ::open(full_path.c_str(), O_RDONLY | O_NOCTTY);

         if(fd >= 0)
            return fd;
         }
      }

   return -1;
   }

}

size_t ProcWalking_EntropySource::poll(RandomNumberGenerator& rng)
   {
   const size_t MAX_FILES_READ_PER_POLL = 2048;

   lock_guard_type<mutex_type> lock(m_mutex);

   if(!m_dir)
      m_dir.reset(new Directory_Walker(m_path));

   m_buf.resize(4096);

   size_t bits = 0;

   for(size_t i = 0; i != MAX_FILES_READ_PER_POLL; ++i)
      {
      int fd = m_dir->next_fd();

      // If we've exhaused this walk of the directory, halt the poll
      if(fd == -1)
         {
         m_dir.reset();
         break;
         }

      ssize_t got = ::read(fd, m_buf.data(), m_buf.size());
      ::close(fd);

      if(got > 0)
         {
         rng.add_entropy(m_buf.data(), static_cast<size_t>(got));

         // Conservative estimate of 4 bits per file
         bits += 4;
         }

      if(bits > 128)
         break;
      }

   return bits;
   }

}
