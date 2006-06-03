#!/usr/bin/python

import os, re, sys

def boost_dir():
    return "/usr/local/src/boost/libs/python/src"

def get_listing_of(dir):
    list = [];
    for root, dirs, files in os.walk(dir):
        list = list + [os.path.join(root, name) for name in files]
    list.sort()
    return list

def produce_output(list):
    def obj_name(source):
        return re.sub(r"^/.*/(.+).cpp$", r"build/boost/\1.o", source)

    def obj_deps(sources):
        def obj_dep(source):
            return obj_name(source) + ": " + source + "\n\t$(CXX) $(BOOST_CFLAGS) -c $< -o $@\n"
        return map(obj_dep, sources);

    def file_lists(list):
        def file_list(list, macro, trans):
            return 'BOOST_' + macro + ' = ' + ' '.join(map(trans, list)) + "\n\n"
        return file_list(list, 'SRC', None) + file_list(list, 'OBJS', obj_name)

    return file_lists(list) + "\n".join(obj_deps(list))

def main():
    print produce_output(get_listing_of(boost_dir()))

if __name__ == "__main__":
    sys.exit(main())
