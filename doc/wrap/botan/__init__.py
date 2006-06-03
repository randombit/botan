from _botan import *

init = LibraryInitializer()

def Filter(name):
    return make_filter(name)

#def Filter(name, key):
#    return make_filter(name, key)
