; This Emacs Lips code defines the indentation style used in Botan. If doesn't
; get everything perfectly correct, but it's pretty close. Copy this code into
; your .emacs file, or use M-x eval-buffer. Make sure to also set
; indent-tabs-mode to nil so spaces are inserted instead.
;
; This style is basically Whitesmiths style with 3 space indents (the Emacs
; "whitesmith" style seems more like a weird Whitesmiths/Allman mutant style).
;
; To activate using this style, open the file you want to edit and run this:
; M-x c-set-style <RET> and then enter "botan".

(setq botan-style '(
   (c-basic-offset . 3)
   (c-comment-only-line-offset . 0)
   (c-offsets-alist
      (c . 0)
      (comment-intro . 0)

      (statement-block-intro . 0)
      (statement-cont . +)

      (substatement . +)
      (substatement-open . +)

      (block-open . +)
      (block-close . 0)

      (defun-open . +)
      (defun-close . 0)
      (defun-block-intro . 0)
      (func-decl-cont . +)

      (class-open . +)
      (class-close . +)
      (inclass . +)
      (access-label . -)
      (inline-open . +)
      (inline-close . 0)

      (extern-lang-open . 0)
      (extern-lang-close . 0)
      (inextern-lang . 0)

      (statement-case-open +)

      (namespace-open . 0)
      (namespace-close . 0)
      (innamespace . 0)

      (label . 0)
      )
))

(add-hook 'c++-mode-common-hook
  (function (lambda () (c-add-style "botan" botan-style nil))))
