
API/ABI Stability
====================

The API and ABI in development branches (those with an odd number, such as 1.11
or 2.1) is subject to change without notice. We don't go out of our way to break
client code, but if a possibility for serious improvement is seen it is taken.

For stable branches (1.10, 2.0) API stability is considered important.
Coorespondingly they see mostly security and bug fixes, or improvements
backported from the devel tree when doing so would not cause problems for
existing code. Code written and working for .0 of a stable release should
continue to work with later releases from the same branch.

However maintaining a consistent ABI while changing a complex C++ API is
exceedingly expensive in development time, and even in the stable branches ABI
breakage may be necessary to fix a security issue or other major bug. If ABI
breakage knowingly occurs in the stable tree it will be documented accordingly
in the release notes and the soname revision will be ticked up.
