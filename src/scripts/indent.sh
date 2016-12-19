#!/bin/sh

ASTYLE_OPTIONS="--style=attach --break-closing-brackets --add-brackets --convert-tabs --indent=spaces=2 --align-pointer=type --align-reference=type --max-code-length=120 --attach-namespaces --indent-switches --indent-preproc-block --keep-one-line-blocks --keep-one-line-statements --indent-preproc-define --unpad-paren --pad-header --mode=c"

astyle $ASTYLE_OPTIONS $*

