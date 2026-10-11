#!/usr/bin/env python3

"""
Generate inline asm multiplication and squaring using MULX with ADCX/ADOX

(C) 2026 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import datetime
import sys

# Registers available for the accumulator window, caller-saved first
POOL = ["r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rbx"]

# Scratch registers: rdx is the multiplier, rax the low half of each
# product, rcx one of the two slots holding the high half
TEMPS = ["rax", "rcx", "rdx"]

# Everything but rbp and rsp
USABLE_REGS = 14

def reg(name):
    return f"%%{name}"

def mem(off, ptr):
    return f"{8 * off}(%[{ptr}])"

def zero(name):
    r32 = name + "d" if name[1:].isdigit() else "e" + name[1:]
    return f"xorl %%{r32}, %%{r32}"

class Asm:
    def __init__(self):
        self.lines = []

    def emit(self, insn, comment=None):
        line = f'      "{insn}\\n\\t"'
        if comment:
            line += f"  // {comment}"
        self.lines.append(line)

    def blank(self):
        self.lines.append("")

    def text(self):
        return "\n".join(self.lines)

def product_chain(asm, products, acc, top, store_first):
    """
    Multiply rdx by each of the x words in products, adding the low halves
    into the accumulator registers acc on the carry flag. The high half of
    each product is carried into the low half of the next on the overflow
    flag, and the carry out of the last word is left in top.

    The first accumulator is final after the first product, so it is stored
    to store_first right away and its register may serve as top. The high
    halves alternate between rcx and top.
    """
    n = len(products)
    assert n >= 2 or top != acc[0]

    def hi(k):
        return top if k % 2 == 1 else "rcx"

    asm.emit("xorl %%eax, %%eax")
    asm.emit(f"mulx {mem(products[0], 'x')}, %%rax, {reg(hi(0))}")
    asm.emit(f"adcx %%rax, {reg(acc[0])}")
    asm.emit(f"movq {reg(acc[0])}, {store_first}")
    for k in range(1, n):
        asm.emit(f"mulx {mem(products[k], 'x')}, %%rax, {reg(hi(k))}")
        asm.emit(f"adox {reg(hi(k - 1))}, %%rax")
        asm.emit(f"adcx %%rax, {reg(acc[k])}")
    last = hi(n - 1)
    asm.emit("movl $0, %%eax")
    asm.emit(f"adox %%rax, {reg(last)}")
    asm.emit(f"adcx %%rax, {reg(last)}")
    if last != top:
        asm.emit(f"movq {reg(last)}, {reg(top)}")

def mul_rows(asm, n, y_in_z):
    """
    Schoolbook multiplication, one row per word of y. The accumulator is a
    window of n registers rotating by one each row; the low word of a row is
    final after its first product and that register then takes the top word.
    """
    def wreg(p):
        return POOL[p % n]

    for k in range(n):
        asm.emit(zero(POOL[k]))

    for i in range(n):
        asm.blank()
        y = mem(n + i, 'z') if y_in_z else mem(i, 'y')
        asm.emit(f"movq {y}, %%rdx", f"row {i}: x * y[{i}]")
        acc = [wreg(i + k) for k in range(n)]
        product_chain(asm, list(range(n)), acc, wreg(i + n), mem(i, 'z'))

    asm.blank()
    for p in range(n, 2 * n):
        asm.emit(f"movq {reg(wreg(p))}, {mem(p, 'z')}")

    return POOL[:n]

def sqr_rows(asm, n):
    """
    Squaring: the products x[i]*x[j] with i < j are accumulated row by row
    into z[1..2n-2], with word w living in register POOL[w % (n-1)]. Then a
    second pass doubles them while adding the squares x[i]^2 at words 2i
    and 2i+1.
    """
    size = n - 1

    def wreg(w):
        return POOL[w % size]

    for w in range(1, n):
        asm.emit(zero(wreg(w)))

    for i in range(n - 1):
        asm.blank()
        asm.emit(f"movq {mem(i, 'x')}, %%rdx", f"x[{i}] * x[{i + 1}..{n - 1}]")
        acc = [wreg(w) for w in range(2 * i + 1, i + n)]
        product_chain(asm, list(range(i + 1, n)), acc, wreg(i + n), mem(2 * i + 1, 'z'))
        # Word 2i+2 is not touched by later rows
        asm.emit(f"movq {reg(wreg(2 * i + 2))}, {mem(2 * i + 2, 'z')}")

    t = reg(POOL[0])
    asm.blank()
    asm.emit(f"movq $0, {mem(2 * n - 1, 'z')}")
    asm.emit("xorl %%eax, %%eax", "double the cross products and add the squares")
    for m in range(n):
        asm.emit(f"movq {mem(m, 'x')}, %%rdx")
        asm.emit("mulx %%rdx, %%rax, %%rcx")
        if m == 0:
            asm.emit(f"movq %%rax, {mem(0, 'z')}")
        else:
            asm.emit(f"movq {mem(2 * m, 'z')}, {t}")
            asm.emit(f"adcx {t}, {t}")
            asm.emit(f"adox %%rax, {t}")
            asm.emit(f"movq {t}, {mem(2 * m, 'z')}")
        asm.emit(f"movq {mem(2 * m + 1, 'z')}, {t}")
        asm.emit(f"adcx {t}, {t}")
        asm.emit(f"adox %%rcx, {t}")
        asm.emit(f"movq {t}, {mem(2 * m + 1, 'z')}")

    return POOL[:size]

def function(name, args, inputs, pool, body, prologue=None):
    assert len(TEMPS) + len(pool) + len(inputs) <= USABLE_REGS
    operands = ", ".join(f'[{i}] "r"({i})' for i in inputs)
    clobbers = ", ".join(f'"{r}"' for r in TEMPS + pool)
    print(f"void {name}({args}) {{")
    if prologue:
        print(f"   {prologue}")
    print("   // clang-format off")
    print("   asm(")
    print(body)
    print("      :")
    print(f"      : {operands}")
    print(f'      : {clobbers}, "cc", "memory");')
    print("   // clang-format on")
    print("}\n")

def main(args = None):
    if args is None:
        args = sys.argv

    if len(args) <= 1:
        sizes = [4, 6, 8, 9]
    else:
        sizes = map(int, args[1:])

    today = datetime.date.today().strftime("%Y-%m-%d")

    print(f"""/*
* Multiplication and squaring using MULX with ADCX/ADOX carry chains
*
* This file was automatically generated by {sys.argv[0]} on {today}
* All manual changes will be lost. Edit the script instead.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
""")

    print("""#include <botan/internal/mp_mulx.h>

#include <botan/mem_ops.h>

namespace Botan {

/*
* Each row multiplies x by one word and adds it into a window of accumulator
* registers. The row's own carries (high half of one product into the low
* half of the next) run on the overflow flag via ADOX, while adding the row
* into the accumulator runs on the carry flag via ADCX; the two chains do not
* wait on each other. The lowest word of a row is final after its first
* product, so it is stored at once and its register takes the row's top word.
*/

// NOLINTBEGIN(*-no-assembler)
""")

    for n in sizes:
        asm = Asm()
        pool = sqr_rows(asm, n)
        function(f"bigint_mulx_sqr{n}", f"word z[{2 * n}], const word x[{n}]", ["z", "x"], pool, asm.text())

        # With three pointers only 8 window registers remain; above that y is
        # staged in the upper half of z, which is not written until the end
        y_in_z = (len(TEMPS) + n + 3 > USABLE_REGS)
        asm = Asm()
        pool = mul_rows(asm, n, y_in_z)
        inputs = ["z", "x"] if y_in_z else ["z", "x", "y"]
        prologue = f"copy_mem(z + {n}, y, {n});" if y_in_z else None
        function(f"bigint_mulx_mul{n}", f"word z[{2 * n}], const word x[{n}], const word y[{n}]", inputs, pool, asm.text(), prologue)

    print("// NOLINTEND(*-no-assembler)")
    print()
    print("}  // namespace Botan")

    return 0

if __name__ == '__main__':
    sys.exit(main())
