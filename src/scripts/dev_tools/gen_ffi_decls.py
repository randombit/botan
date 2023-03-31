#!/usr/bin/env python3

"""
Automatically generate declarations for the FFI layer

(C) 2019, 2023 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import traceback
from pycparser import c_ast, parse_file

ffi_header = 'src/lib/ffi/ffi.h'

def to_ctype(typ, is_ptr):

    if typ.startswith('botan_') and typ.endswith('_t'):
        return 'c_void_p'

    if typ == 'botan_view_ctx':
        return 'c_void_p'

    if typ == 'botan_view_bin_fn':
        return 'VIEW_BIN_CALLBACK'
    if typ == 'botan_view_str_fn':
        return 'VIEW_STR_CALLBACK'

    if is_ptr is False:
        if typ == 'uint32':
            return 'c_uint32'
        elif typ == 'size_t':
            return 'c_size_t'
        elif typ == 'uint8_t':
            return 'c_uint8'
        elif typ == 'uint32_t':
            return 'c_uint32'
        elif typ == 'uint64_t':
            return 'c_uint64'
        elif typ == 'int':
            return 'c_int'
        elif typ == 'unsigned':
            return 'c_uint'
    else:
        if typ == 'void':
            return 'c_void_p'
        elif typ in ['char', 'uint8_t']: # hack
            return 'c_char_p'
        elif typ == 'size_t':
            return 'POINTER(c_size_t)'
        #elif typ == 'uint8_t':
        #    return 'POINTER(c_uint8)'
        elif typ == 'uint32_t':
            return 'POINTER(c_uint32)'
        elif typ == 'uint64_t':
            return 'POINTER(c_uint64)'
        elif typ == 'int':
            return 'POINTER(c_int)'

    raise Exception("Unknown type %s/%d" % (typ, is_ptr))

class FuncDefVisitor(c_ast.NodeVisitor):
    def __init__(self):
        self.fn_decls = []

    def emit_decls(self):
        decls = ''
        for (fn_name, fn_args) in self.fn_decls:
            decl = "    ffi_api(dll.%s," % (fn_name)
            if len(fn_args) > 4:
                decl += "\n            "
            else:
                decl += ' '

            decl += '[' + ', '.join(fn_args) + '])\n'

            decls += decl
        return decls

    def visit_FuncDecl(self, node):

        if not isinstance(node.type, c_ast.TypeDecl):
            #print("ignoring", node.type)
            return

        if node.type.type.names != ['int']:
            #print("ignoring", node.type)
            return

        # all functions returning ints:
        fn_name = node.type.declname

        ignored = [
            'botan_view_bin_fn',
            'botan_view_str_fn',
            'botan_same_mem', # deprecated
            'botan_mceies_encrypt', # dead
            'botan_mceies_decrypt', # dead
            'botan_rng_init_custom', # fixme
        ]
        if fn_name in ignored:
            return

        fn_args = []

        try:
            for param in node.args.params:

                is_ptr = False
                typ = None

                if isinstance(param.type, c_ast.PtrDecl):
                    is_ptr = True

                    if isinstance(param.type.type, c_ast.PtrDecl):
                        typ = param.type.type.type.type.names[0]
                    else:
                        typ = param.type.type.type.names[0]
                elif isinstance(param.type, c_ast.ArrayDecl):
                    is_ptr = True
                    typ = param.type.type.type.names[0]
                else:
                    typ = param.type.type.names[0]

                ctype = to_ctype(typ, is_ptr)
                fn_args.append(ctype)

            self.fn_decls.append((fn_name, fn_args))
        except Exception as e:
            print(traceback.format_exc())
            print("FAILED for '%s': %s" % (fn_name, e))

ast = parse_file(ffi_header, use_cpp=True, cpp_args=['-Ibuild/include', '-std=c89', '-DBOTAN_DLL=', '-DBOTAN_NO_DEPRECATED_WARNINGS'])
#print(ast)
v = FuncDefVisitor()
v.visit(ast)

#print("\n".join(v.fn_decls))
print(v.emit_decls())
