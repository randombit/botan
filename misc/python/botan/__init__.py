from _botan import *

init = LibraryInitializer()

def Filter(name):
    return make_filter(name)

def Pipe(*filters):
    pipe = PipeObj();
    for filter in filters:
        if filter:
            pipe.append(filter)
    return pipe

#def Filter(name, key):
#    return make_filter(name, key)
