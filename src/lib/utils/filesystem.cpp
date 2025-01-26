/*
* (C) 2015,2017,2019 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/exceptn.h>

#include <botan/assert.h>
#include <botan/internal/filesystem.h>
#include <algorithm>
#include <deque>
#include <memory>
#include <sstream>

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   #include <dirent.h>
   #include <functional>
   #include <sys/stat.h>
   #include <sys/types.h>
#elif defined(BOTAN_TARGET_OS_HAS_WIN32)
   #define NOMINMAX 1
   #define _WINSOCKAPI_  // stop windows.h including winsock.h
   #include <windows.h>
#endif

namespace Botan {

namespace {

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)

std::vector<std::string> impl_readdir(std::string_view dir_path) {
   std::vector<std::string> out;
   std::deque<std::string> dir_list;
   dir_list.push_back(std::string(dir_path));

   while(!dir_list.empty()) {
      const std::string cur_path = dir_list[0];
      dir_list.pop_front();

      std::unique_ptr<DIR, std::function<int(DIR*)>> dir(::opendir(cur_path.c_str()), ::closedir);

      if(dir) {
         while(struct dirent* dirent = ::readdir(dir.get())) {
            const std::string filename = dirent->d_name;
            if(filename == "." || filename == "..") {
               continue;
            }

            std::ostringstream full_path_sstr;
            full_path_sstr << cur_path << "/" << filename;
            const std::string full_path = full_path_sstr.str();

            struct stat stat_buf;

            if(::stat(full_path.c_str(), &stat_buf) == -1) {
               continue;
            }

            if(S_ISDIR(stat_buf.st_mode)) {
               dir_list.push_back(full_path);
            } else if(S_ISREG(stat_buf.st_mode)) {
               out.push_back(full_path);
            }
         }
      }
   }

   return out;
}

#elif defined(BOTAN_TARGET_OS_HAS_WIN32)

std::vector<std::string> impl_win32(std::string_view dir_path) {
   std::vector<std::string> out;
   std::deque<std::string> dir_list;
   dir_list.push_back(std::string(dir_path));

   while(!dir_list.empty()) {
      const std::string cur_path = dir_list[0];
      dir_list.pop_front();

      WIN32_FIND_DATAA find_data;
      HANDLE dir = ::FindFirstFileA((cur_path + "/*").c_str(), &find_data);

      if(dir != INVALID_HANDLE_VALUE) {
         do {
            const std::string filename = find_data.cFileName;
            if(filename == "." || filename == "..")
               continue;
            const std::string full_path = cur_path + "/" + filename;

            if(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
               dir_list.push_back(full_path);
            } else {
               out.push_back(full_path);
            }
         } while(::FindNextFileA(dir, &find_data));
      }

      ::FindClose(dir);
   }

   return out;
}
#endif

}  // namespace

bool has_filesystem_impl() {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   return true;
#elif defined(BOTAN_TARGET_OS_HAS_WIN32)
   return true;
#else
   return false;
#endif
}

std::vector<std::string> get_files_recursive(std::string_view dir) {
   std::vector<std::string> files;

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   files = impl_readdir(dir);
#elif defined(BOTAN_TARGET_OS_HAS_WIN32)
   files = impl_win32(dir);
#else
   BOTAN_UNUSED(dir);
   throw No_Filesystem_Access();
#endif

   std::sort(files.begin(), files.end());

   return files;
}

}  // namespace Botan
