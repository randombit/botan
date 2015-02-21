/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/fs.h>
#include <algorithm>
#include <deque>

#if defined(BOTAN_HAS_BOOST_FILESYSTEM)
  #include <boost/filesystem.hpp>

#elif defined(BOTAN_TARGET_OS_HAS_READDIR)
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <dirent.h>
#endif

namespace Botan {

std::vector<std::string>
list_all_readable_files_in_or_under(const std::string& dir_path)
   {
   std::vector<std::string> paths;

#if defined(BOTAN_HAS_BOOST_FILESYSTEM)
   namespace fs = boost::filesystem;

   fs::recursive_directory_iterator end;
   for(fs::recursive_directory_iterator dir(dir_path); dir != end; ++dir)
      {
      if(fs::is_regular_file(dir->path()))
         paths.push_back(dir->path().string());
      }

#elif defined(BOTAN_TARGET_OS_HAS_READDIR)

   std::deque<std::string> dir_list;
   dir_list.push_back(dir_path);

   while(!dir_list.empty())
      {
      const std::string cur_path = dir_list[0];
      dir_list.pop_front();

      std::unique_ptr<DIR, std::function<int (DIR*)>> dir(::opendir(cur_path.c_str()), ::closedir);

      if(dir)
         {
         while(struct dirent* dirent = ::readdir(dir.get()))
            {
            const std::string filename = dirent->d_name;
            if(filename == "." || filename == "..")
               continue;
            const std::string full_path = cur_path + '/' + filename;

            struct stat stat_buf;

            if(::lstat(full_path.c_str(), &stat_buf) == -1)
               continue;

            if(S_ISDIR(stat_buf.st_mode))
               dir_list.push_back(full_path);
            else if(S_ISREG(stat_buf.st_mode))
               paths.push_back(full_path);
            }
         }
      }
#else
  #warning "No filesystem access enabled"
#endif

   std::sort(paths.begin(), paths.end());

   return paths;
   }

}

