/*
* FTW EntropySource
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/es_ftw.h>
#include <botan/secmem.h>
#include <cstring>
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

class Directory_Walker : public FTW_EntropySource::File_Descriptor_Source
   {
   public:
      Directory_Walker(const std::string& root) { add_directory(root); }
      ~Directory_Walker();

      int next_fd();
   private:
      void add_directory(const std::string&);

      std::deque<std::pair<DIR*, std::string> > dirs;
   };

void Directory_Walker::add_directory(const std::string& dirname)
   {
   DIR* dir = ::opendir(dirname.c_str());
   if(dir)
      dirs.push_back(std::make_pair(dir, dirname));
   }

Directory_Walker::~Directory_Walker()
   {
   while(dirs.size())
      {
      ::closedir(dirs[0].first);
      dirs.pop_front();
      }
   }

int Directory_Walker::next_fd()
   {
   while(dirs.size())
      {
      std::pair<DIR*, std::string> dirinfo = dirs[0];

      struct dirent* entry = ::readdir(dirinfo.first);

      if(!entry)
         {
         ::closedir(dirinfo.first);
         dirs.pop_front();
         continue;
         }

      const std::string filename = entry->d_name;

      if(filename == "." || filename == "..")
         continue;

      const std::string full_path = dirinfo.second + '/' + filename;

      struct stat stat_buf;
      if(::lstat(full_path.c_str(), &stat_buf) == -1)
         continue;

      if(S_ISDIR(stat_buf.st_mode))
         add_directory(full_path);
      else if(S_ISREG(stat_buf.st_mode) && (stat_buf.st_mode & S_IROTH))
         {
         int fd = ::open(full_path.c_str(), O_RDONLY | O_NOCTTY);

         if(fd > 0)
            return fd;
         }
      }

   return -1;
   }

}

/**
* FTW_EntropySource Constructor
*/
FTW_EntropySource::FTW_EntropySource(const std::string& p) : path(p)
   {
   dir = 0;
   }

/**
* FTW_EntropySource Destructor
*/
FTW_EntropySource::~FTW_EntropySource()
   {
   delete dir;
   }

void FTW_EntropySource::poll(Entropy_Accumulator& accum)
   {
   const u32bit MAX_FILES_READ_PER_POLL = 1024;

   if(!dir)
      dir = new Directory_Walker(path);

   MemoryRegion<byte>& io_buffer = accum.get_io_buffer(128);

   for(u32bit i = 0; i != MAX_FILES_READ_PER_POLL; ++i)
      {
      int fd = dir->next_fd();

      // If we've exhaused this walk of the directory, halt the poll
      if(fd == -1)
         {
         delete dir;
         dir = 0;
         break;
         }

      ssize_t got = ::read(fd, io_buffer.begin(), io_buffer.size());
      ::close(fd);

      if(got > 0)
         accum.add(io_buffer.begin(), got, .01);

      if(accum.polling_goal_achieved())
         break;
      }
   }

}
