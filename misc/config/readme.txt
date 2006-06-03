
mkconfig.pl is the main deal; it pulls in little (or not-so-little...) pieces
of code from the code/ directory and also parses the config files in arch/,
cc/, and os/ to generate tables for the code to chew on.

There isn't too much documentation. For examples, cc/gcc, os/linux, and
arch/ia32 are good starts.

This stuff isn't going to be particularly useful, unless you need/want to fix
an error, or add support for a new CPU, operating system, or compiler. If you
do, please submit the changes back to the main project so everyone can benefit.

This code, including the config files, is in the public domain, and you may
do with it as you wish.
