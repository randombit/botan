# (C) 2025 Jack Lloyd
#     2025 René Meusel, Rohde & Schwarz Cybersecurity
#
# Botan is released under the Simplified BSD License (see license.txt)
#

"""
User-defined GDB CLI command to help in testing GCC's stack scrubbing
annotations. See also src/scripts/test_strubbed_symbols.py for details.

This can be used in interactive GDB sessions for debugging and development.

   $> gdb -x src/scripts/gdb/strubtest.py ./botan
   (gdb) strubtest Botan::SHA_256::compress_digest
   strubtest setup done
   (gdb) run hash --algo=SHA-256 readme.rst
   Success: stackframe of Botan::SHA_256::compress_digest contains 10176 zero bytes after invocation
   ECD8814EDC180601831FDAD7DEDCF24D57F9F002295346E7D558C941AD318F8E readme.rst
"""

import gdb

def stack_pointer(frame):
    return frame.read_register('sp')

def frame_pointer(frame):
    return frame.read_register('fp')

def report_error(error):
    gdb.write(f"Error: {error}\n", gdb.STDERR)

def report_status(status):
    gdb.write(f"{status}\n", gdb.STDOUT)

class PostStrubLocation(gdb.FinishBreakpoint):
    """
    This (temporary) breakpoint is placed by the StrubTarget at the end of the
    "virtual wrapper" GCC introduced to scrub the target's stackframe. When hit
    it validates that the this stackframe indeed contains zero bytes only.
    """

    def __init__(self, caller_frame, target_frame, function_name):
        super().__init__(caller_frame, internal=True)
        self.function_name = function_name
        self.payload_stack_memory = (stack_pointer(target_frame),
                                     frame_pointer(target_frame) - stack_pointer(target_frame))

    def stackframe_memory(self):
        return gdb.selected_inferior().read_memory(*self.payload_stack_memory)

    def stackframe_size(self):
        return self.payload_stack_memory[1]

    def is_stackframe_scrubbed(self):
        return all(b'\x00' == b for b in self.stackframe_memory())

    def stop(self):
        if not self.is_stackframe_scrubbed():
            report_error(f"{self.function_name} didn't get its stack frame scrubbed after usage")
        else:
            report_status(f"Success: stackframe of {self.function_name} contains {self.stackframe_size()} zero bytes after invcoation")

class StrubTarget(gdb.Breakpoint):
    """
    This special breakpoint shall be set to a symbol that was marked with
    GCC's __attribute__(strub("internal")). When hit, it will note the size of
    its stackframe and set another temporary breakpoint at the end of the
    "virtual wrapper" GCC introduced, see PostStrubLocation. There, we'll check
    if the now-invalidated stackframe indeed contains only zero bytes.
    """

    def __init__(self, function_name):
        super().__init__(function_name, internal=True)
        self.function_name = function_name

    def stop(self):
        target_frame = gdb.newest_frame()
        caller_frame = gdb.newest_frame().older()

        # __attribute__( strub("internal") ) creates a "virtual wrapper" around
        # the annotated function. This wrapper has the same symbol name as the
        # actual target function. To tell them apart, we simply _assume_ that
        # the wrapper is always at the lower address in the binary. This may
        # change in the future or differ across compiler versions!
        if len(self.locations) > 1:
            wrapper_address = min(loc.address for loc in self.locations)
            if wrapper_address == target_frame.pc():
                return False

        # Set a temporary breakpoint after the "virtual wrapper" (caller_frame)
        # has returned. This is just after the stack scrubbing was performed.
        PostStrubLocation(caller_frame, target_frame, self.function_name)

        # Don't stop for interactive inspection at this location
        return False

class StrubTest(gdb.Command):
    """
    User-defined gdb command to set up a stack scrubbing (strub) test allowing
    to check that the invocation of a given symbol gets its stack cleared after
    returning. Stack scrubbing is a feature in GCC 14 and newer and is enabled
    for relevant functions using `./configure.py --enable-stack-scrubbing`.
    """

    def __init__(self):
        super().__init__("strubtest", gdb.COMMAND_USER)

    def invoke(self, argstring, _):
        if not argstring:
            report_error("a target symbol name is required")
            return

        bp = StrubTarget(argstring)
        if bp.pending:
            bp.delete()
            report_error(f"the provided symbol '{argstring}' does not appear to be available")

        report_status("strubtest setup done")

# Register the custom command with GDB. It may be invoked from GDB's CLI:
#
#  strubtest <annotated symbol, e.g. "Botan::SHA_256::compress_digest">
#
# Any time a test program (compiled with --enable-stack-scrubbing --debug-mode)
# invokes this symbol GDB will either print "Success: ..." or "Error: ...",
# depending on the outcome of the test.
StrubTest()
